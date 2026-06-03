import json, ipaddress, time, hashlib, math
from pathlib import Path

LOG_FILE = Path("lms-stage-access.log")


class HyperLogLog:
    def __init__(self, p=14):
        if not (4 <= p <= 20):
            raise ValueError("p must be in [4, 20]")
        self.p = p
        self.m = 1 << p
        self.registers = [0] * self.m
        if self.m == 16:
            self.alpha = 0.673
        elif self.m == 32:
            self.alpha = 0.697
        elif self.m == 64:
            self.alpha = 0.709
        else:
            self.alpha = 0.7213 / (1 + 1.079 / self.m)

    @staticmethod
    def _hash(value: str) -> int:
        return int.from_bytes(hashlib.sha1(value.encode("utf-8")).digest()[:8], "big")

    @staticmethod
    def _rho(w: int, bits: int) -> int:
        if w == 0:
            return bits + 1
        return bits - w.bit_length() + 1

    def add(self, value: str) -> None:
        x = self._hash(value)
        idx = x >> (64 - self.p)
        w = x & ((1 << (64 - self.p)) - 1)
        rank = self._rho(w, 64 - self.p)
        if rank > self.registers[idx]:
            self.registers[idx] = rank

    def count(self) -> int:
        indicator = sum(2.0**-r for r in self.registers)
        estimate = self.alpha * self.m * self.m / indicator
        zeros = self.registers.count(0)
        if estimate <= 2.5 * self.m and zeros:
            estimate = self.m * math.log(self.m / zeros)
        return round(estimate)


def is_valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def load_ip_addresses(path: Path):
    """Generator: reads a large JSON-lines log and yields valid remote_addr IPs only."""
    with path.open("r", encoding="utf-8", errors="ignore") as file:
        for line in file:
            try:
                record = json.loads(line)
                ip = record.get("remote_addr")
            except json.JSONDecodeError:
                continue
            if isinstance(ip, str) and is_valid_ip(ip):
                yield ip


def exact_count(path: Path) -> int:
    return len(set(load_ip_addresses(path)))


def hll_count(path: Path, p: int = 14) -> int:
    hll = HyperLogLog(p=p)
    for ip in load_ip_addresses(path):
        hll.add(ip)
    return hll.count()


def timed(func, *args, **kwargs):
    start = time.perf_counter()
    result = func(*args, **kwargs)
    elapsed = time.perf_counter() - start
    return result, elapsed


def main():
    exact_result, exact_time = timed(exact_count, LOG_FILE)
    hll_result, hll_time = timed(hll_count, LOG_FILE)
    error = abs(hll_result - exact_result) / exact_result * 100 if exact_result else 0

    print("Результати порівняння:")
    print(f'{"":30} {"Точний підрахунок":>20} {"HyperLogLog":>15}')
    print(f'{"Унікальні елементи":30} {exact_result:>20.1f} {hll_result:>15.1f}')
    print(f'{"Час виконання (сек.)":30} {exact_time:>20.4f} {hll_time:>15.4f}')
    print(f'{"Похибка HyperLogLog (%)":30} {0:>20.2f} {error:>15.2f}')


if __name__ == "__main__":
    main()
