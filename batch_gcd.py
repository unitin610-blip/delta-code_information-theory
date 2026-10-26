from math import gcd
from time import perf_counter


def build_product_tree(numbers):
    """Build a tree of products of the input integers."""
    if not numbers:
        return []

    levels = [list(numbers)]

    while len(levels[-1]) > 1:
        current = levels[-1]
        next_level = [
            current[i] * current[i + 1]
            for i in range(0, len(current) - 1, 2)
        ]

        if len(current) % 2:
            next_level.append(current[-1])

        levels.append(next_level)

    return levels


def build_remainder_tree(product_tree):
    """Propagate remainders to calculate total_product mod n_i^2."""
    if not product_tree:
        return []

    remainders = [None] * len(product_tree)
    remainders[-1] = [product_tree[-1][0]]

    for level in range(len(product_tree) - 2, -1, -1):
        products = product_tree[level]
        parent_remainders = remainders[level + 1]
        current_remainders = []

        for i, value in enumerate(products):
            parent_index = i // 2
            current_remainders.append(
                parent_remainders[parent_index] % (value * value)
            )

        remainders[level] = current_remainders

    return remainders


def batch_gcd(numbers):
    """Return each modulus and its shared-factor GCD candidate."""
    if any(n <= 1 for n in numbers):
        raise ValueError("Every modulus must be greater than 1.")

    if len(set(numbers)) != len(numbers):
        raise ValueError(
            "Duplicate moduli detected; handle duplicates separately."
        )

    tree = build_product_tree(numbers)
    remainders = build_remainder_tree(tree)
    results = []

    for n, remainder in zip(numbers, remainders[0]):
        candidate = gcd(n, remainder // n)
        results.append((n, candidate))

    return results


if __name__ == "__main__":
    sample = [11413, 12827]
    start = perf_counter()
    results = batch_gcd(sample)
    elapsed = perf_counter() - start

    for n, factor in results:
        if 1 < factor < n:
            print(f"n={n}: shared factor found: {factor}")
        elif factor == n:
            print(f"n={n}: ambiguous result; investigate duplicates or multiple shared factors")
        else:
            print(f"n={n}: no shared factor detected")

    print(f"Keys checked: {len(sample)}")
    print(f"Elapsed time: {elapsed:.6f} seconds")
