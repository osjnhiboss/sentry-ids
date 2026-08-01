"""
Simulates access-pattern data for the IDS to learn from.

Why synthetic data instead of a public dataset like NSL-KDD/CICIDS?
Those datasets model raw *network* traffic. This proposal targets a
different signal: application-layer access patterns aimed at
confidential data (IDOR probing, mass record enumeration, off-hours
scraping, brute-forced auth). There's no standard public dataset for
that exact behavior, so we simulate one with realistic feature
distributions. This also means you can regenerate/rebalance data
easily, and it's fully explainable in your report (you define exactly
what "normal" and "intrusive" mean).

Features (per request, computed over a rolling window):
- requests_per_minute:            request rate from this user/IP
- unique_records_accessed_5min:   breadth of record IDs touched recently
- off_hours:                      1 if outside 08:00-20:00
- failed_auth_attempts_10min:     recent failed logins from this actor
- bytes_transferred_5min:         data volume pulled recently
- is_confidential_endpoint:       1 if hitting a confidential-data route

Label:
- 0 = normal user behavior
- 1 = intrusive / unauthorized-access attempt
"""
import numpy as np
import pandas as pd

RNG = np.random.default_rng(42)


def simulate_normal(n):
    return pd.DataFrame({
        "requests_per_minute": RNG.normal(3, 1.5, n).clip(0.1, None),
        "unique_records_accessed_5min": RNG.poisson(2, n),
        "off_hours": RNG.choice([0, 1], n, p=[0.9, 0.1]),
        "failed_auth_attempts_10min": RNG.poisson(0.1, n),
        "bytes_transferred_5min": RNG.normal(5000, 2000, n).clip(100, None),
        "is_confidential_endpoint": RNG.choice([0, 1], n, p=[0.7, 0.3]),
        "label": 0,
    })


def simulate_malicious(n):
    # Mix of three attack styles: enumeration/exfiltration, off-hours scraping,
    # credential brute-forcing / IDOR probing.
    n_enum = n // 3
    n_scrape = n // 3
    n_brute = n - n_enum - n_scrape

    enum_df = pd.DataFrame({
        "requests_per_minute": RNG.normal(45, 15, n_enum).clip(5, None),
        "unique_records_accessed_5min": RNG.poisson(60, n_enum),
        "off_hours": RNG.choice([0, 1], n_enum, p=[0.6, 0.4]),
        "failed_auth_attempts_10min": RNG.poisson(1, n_enum),
        "bytes_transferred_5min": RNG.normal(80000, 30000, n_enum).clip(1000, None),
        "is_confidential_endpoint": RNG.choice([0, 1], n_enum, p=[0.1, 0.9]),
    })

    scrape_df = pd.DataFrame({
        "requests_per_minute": RNG.normal(15, 6, n_scrape).clip(2, None),
        "unique_records_accessed_5min": RNG.poisson(25, n_scrape),
        "off_hours": RNG.choice([0, 1], n_scrape, p=[0.15, 0.85]),
        "failed_auth_attempts_10min": RNG.poisson(0.3, n_scrape),
        "bytes_transferred_5min": RNG.normal(40000, 15000, n_scrape).clip(500, None),
        "is_confidential_endpoint": RNG.choice([0, 1], n_scrape, p=[0.2, 0.8]),
    })

    brute_df = pd.DataFrame({
        "requests_per_minute": RNG.normal(20, 8, n_brute).clip(3, None),
        "unique_records_accessed_5min": RNG.poisson(3, n_brute),
        "off_hours": RNG.choice([0, 1], n_brute, p=[0.5, 0.5]),
        "failed_auth_attempts_10min": RNG.poisson(8, n_brute),
        "bytes_transferred_5min": RNG.normal(3000, 1500, n_brute).clip(100, None),
        "is_confidential_endpoint": RNG.choice([0, 1], n_brute, p=[0.4, 0.6]),
    })

    out = pd.concat([enum_df, scrape_df, brute_df], ignore_index=True)
    out["label"] = 1
    return out


def build_dataset(n_normal=4000, n_malicious=1000, path="backend/data/access_logs.csv"):
    df = pd.concat([simulate_normal(n_normal), simulate_malicious(n_malicious)], ignore_index=True)
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)  # shuffle
    df.to_csv(path, index=False)
    print(f"Wrote {len(df)} rows ({n_normal} normal / {n_malicious} malicious) to {path}")
    return df


if __name__ == "__main__":
    build_dataset()
