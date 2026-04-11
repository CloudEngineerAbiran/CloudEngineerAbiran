"""
Problem
-------
Given authentication logs where each record contains:
1) username (str)
2) timestamp in minutes (int)
3) failure flag (bool)

Return all users who had 3 or more failed login attempts within ANY 5-minute window.

DSA / Algorithm
---------------
Data Structure:
- Hash map (dict): user -> list of failed timestamps
- Two pointers / sliding window over each user's sorted failed timestamps

Why this works:
- For each user, we only care about failed attempts.
- If timestamps are sorted, a window [left, right] is valid when:
      timestamps[right] - timestamps[left] <= 5
- As right expands, move left forward whenever window exceeds 5 minutes.
- If at any point window size >= 3, this user qualifies.

Time Complexity:
- Let n be total logs and f be total failed logs.
- Grouping failures: O(n)
- Sorting each user's failed timestamps: overall O(f log f) in worst case
- Sliding window scan: O(f)
- Total: O(n + f log f)

Space Complexity:
- O(f) for storing failed timestamps.

Notes:
- A 5-minute window here is interpreted as inclusive boundary:
  difference <= 5 (e.g., 10, 13, 15 qualifies because 15 - 10 = 5).
"""

from collections import defaultdict
from typing import Iterable, List, Sequence, Tuple

LogRecord = Tuple[str, int, bool]  # (username, timestamp_in_minutes, is_failure)


def users_with_suspicious_failures(logs: Sequence[LogRecord]) -> List[str]:
    """
    Return sorted list of usernames with >=3 failed attempts within any 5-minute window.

    Args:
        logs: Iterable of (username, timestamp, is_failure)

    Returns:
        Sorted list of suspicious usernames.
    """
    failed_by_user = defaultdict(list)

    # 1) Collect failed timestamps per user.
    for username, timestamp, is_failure in logs:
        if is_failure:
            failed_by_user[username].append(timestamp)

    suspicious_users = []

    # 2) For each user, sort and apply sliding window.
    for username, times in failed_by_user.items():
        times.sort()
        left = 0

        for right in range(len(times)):
            while times[right] - times[left] > 5:
                left += 1

            # Current window size = right - left + 1
            if right - left + 1 >= 3:
                suspicious_users.append(username)
                break

    return sorted(suspicious_users)


def main() -> None:
    """Small runnable demo."""
    sample_logs: List[LogRecord] = [
        ("alice", 1, True),
        ("alice", 3, True),
        ("alice", 5, True),   # alice qualifies: 1,3,5 within 5 mins
        ("bob", 2, True),
        ("bob", 10, True),
        ("bob", 20, True),    # bob does NOT qualify
        ("carol", 7, False),
        ("carol", 8, True),
        ("carol", 12, True),
        ("carol", 13, True),  # carol qualifies: 8,12,13 within 5 mins
    ]

    result = users_with_suspicious_failures(sample_logs)
    print("Users with >=3 failed logins in a 5-minute window:", result)


if __name__ == "__main__":
    main()
