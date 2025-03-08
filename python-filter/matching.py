import re
from typing import Dict, List


def check_pattern_match(text: str, pattern: str) -> bool:
    """
    Check if text matches the given pattern:
    - If pattern contains , use regex match
    - If pattern doesn't contain , check if text contains pattern

    Args:
        text (str): Text to check
        pattern (str): Pattern to match against

    Returns:
        bool: True if matches pattern, False otherwise

    Examples:
        >>> check_pattern_match("file.xml", ".xml")  # Contains check
        True
        >>> check_pattern_match("file.xml", "*.xml*")  # Regex match
        True
    """
    try:
        # If no asterisk in pattern, do simple contains check
        if "*" not in pattern:
            return pattern in text

        # If pattern has asterisk, use regex match
        return bool(re.match(pattern, text))
    except re.error as e:
        print(f"Invalid regex pattern: {e}")
        return False


def filter_bypassuac_attempt(records: List[Dict]) -> List[Dict]:
    """
    Filter records for UAC bypass attempts based on specific patterns and conditions

    Args:
        records (List[Dict]): List of event records to check

    Returns:
        List[Dict]: Filtered list of records matching UAC bypass patterns
    """
    results: List[Dict] = []

    for record in records:
        try:
            # Check basic conditions first
            if (
                record["data"]["win"]["system"]["eventID"] == "1"
                and record["data"]["win"]["eventdata"]["integrityLevel"] == "High"
            ):

                # Check all conditions

                # Condition 1: DISM bypass
                try:
                    parent_cmd = record["data"]["win"]["eventdata"][
                        "parentCommandLine"
                    ].lower()
                    image = record["data"]["win"]["eventdata"]["image"].lower()
                    if all(
                        check_pattern_match(pattern=x, text=parent_cmd)
                        for x in ["c:\\\\windows\\\\system32\\\\dism.exe", ".xml"]
                    ) and all(
                        check_pattern_match(pattern=x, text=image)
                        for x in ["c:\\\\users\\\\", "\\\\dismhost.exe"]
                    ):
                        results.append(record)
                except Exception:
                    continue

                # Condition 2: Fodhelper bypass
                try:
                    parent_image = record["data"]["win"]["eventdata"][
                        "parentImage"
                    ].lower()
                    if check_pattern_match(
                        pattern="c:\\\\windows\\\\system32\\\\fodhelper.exe",
                        text=parent_image,
                    ) and any(
                        check_pattern_match(pattern=f"{x}", text=image)
                        for x in [
                            "cmd.exe",
                            "powershell.exe",
                            "rundll32.exe",
                            "regsvr32.exe",
                        ]
                    ):
                        results.append(record)
                except Exception:
                    continue

                # Condition 3: WUSA bypass
                try:
                    cmd_line = record["data"]["win"]["eventdata"]["commandLine"].lower()
                    current_dir = (
                        record["data"]["win"]["eventdata"]
                        .get("currentDirectory", "")
                        .lower()
                    )
                    if (
                        check_pattern_match(
                            pattern="c:\\\\windows\\\\system32\\\\wusa.exe",
                            text=cmd_line,
                        )
                        and check_pattern_match(pattern="/quiet", text=cmd_line)
                        and current_dir == "c:\\\\windows\\\\system32\\\\"
                        and check_pattern_match(
                            pattern="c:\\\\windows\\\\explorer.exe", text=parent_image
                        )
                    ):
                        results.append(record)
                except Exception:
                    continue

                # Condition 4: Cleanmgr bypass
                try:
                    if check_pattern_match(
                        pattern="cleanmgr.exe /autoclean", text=cmd_line
                    ) and check_pattern_match(
                        pattern="c:\\\\windows\\\\explorer.exe", text=parent_image
                    ):
                        results.append(record)
                except Exception:
                    continue

                # Condition 5: DCCW bypass
                try:
                    if check_pattern_match(
                        pattern="c:\\\\windows\\\\dccw.exe", text=parent_image
                    ) and check_pattern_match(
                        pattern="c:\\\\windows\\\\system32\\\\cttune.exe", text=image
                    ):
                        results.append(record)
                except Exception:
                    continue

                # Condition 6: OSK bypass
                try:
                    if check_pattern_match(
                        pattern="c:\\\\program files\\\\windows media player\\\\osk.exe",
                        text=image,
                    ):
                        results.append(record)
                except Exception:
                    continue

                # Condition 7: SLUI bypass
                try:
                    if check_pattern_match(
                        "c:\\\\windows\\\\system32\\\\slui.exe", parent_image
                    ) and any(
                        check_pattern_match(pattern=f"{x}", text=image)
                        for x in [
                            "cmd.exe",
                            "powershell.exe",
                            "rundll32.exe",
                            "regsvr32.exe",
                        ]
                    ):
                        results.append(record)
                except Exception:
                    continue

        except Exception as e:
            # Log the error if needed
            continue

    return results


def filter_malicious_shell_connect(records: List[Dict]) -> List[Dict]:
    """
    Detect malicious PowerShell code attempting to connect outside.
    Correlates records by processId to find:
    1. PowerShell commands with suspicious parameters/methods
    2. Network connection messages from the same process

    Args:
        records (List[Dict]): List of event records to check

    Returns:
        List[Dict]: Filtered list of suspicious records
    """
    # Track suspicious processes and their records
    suspicious_processes = {}  # processId -> [records]

    # Suspicious PowerShell parameters and methods
    suspicious_patterns = [
        "-nop",
        "-w",
        "hidden",
        "FromBase64String".lower(),
        "GzipStream".lower(),
        "MemoryStream".lower(),
    ]

    for record in records:
        try:
            event_data = record["data"]["win"]["eventdata"]
            system_data = record["data"]["win"]["system"]
            process_id = event_data.get("processId")

            if not process_id:
                continue

            # # Check for malicious PowerShell commands
            try:
                cmd_line = event_data["commandLine"].lower()
                image = event_data["image"].lower()
                
                # Check if it's PowerShell with suspicious patterns
                if check_pattern_match(pattern="powershell.exe", text=image) and any(
                    check_pattern_match(pattern=pattern, text=cmd_line)
                    for pattern in suspicious_patterns
                ):
                    if process_id not in suspicious_processes:
                        suspicious_processes[process_id] = []
                    suspicious_processes[process_id].append(record)
            except Exception:
                pass

            # Check for network connection messages
            try:
                message = system_data["message"].lower()
                if check_pattern_match(
                    pattern="network connection detected", text=message
                ):
                    if process_id not in suspicious_processes:
                        suspicious_processes[process_id] = []
                    suspicious_processes[process_id].append(record)
            except Exception:
                pass

        except Exception:
            continue

    # Filter processes that have both suspicious PowerShell and network connection
    results = []
    for process_id, proc_records in suspicious_processes.items():
        if len(proc_records) >= 2:  # Must have at least 2 records
            # Check if process has both conditions
            has_powershell = False
            has_network = False

            for record in proc_records:
                try:
                    # Check PowerShell condition
                    if check_pattern_match(
                        pattern="powershell.exe",
                        text=record["data"]["win"]["eventdata"]["image"].lower(),
                    ):
                        has_powershell = True

                    # Check network condition
                    if check_pattern_match(
                        pattern="network connection detected",
                        text=record["data"]["win"]["system"]["message"].lower(),
                    ):
                        has_network = True
                except Exception:
                    continue

            # If both conditions are met, add all records for this process
            if has_powershell and has_network:
                results.extend(proc_records)

    return results

from typing import Dict, List

def filter_lsass_access_attempt(records: List[Dict]) -> List[Dict]:
    """
    Filter records for potential LSASS memory access attempts based on Sysmon Event ID 10.
    Detects attempts to access LSASS memory with specific granted access masks that are 
    commonly associated with credential dumping.

    Args:
        records (List[Dict]): List of event records to check

    Returns:
        List[Dict]: Filtered list of records matching LSASS access patterns
    """
    results: List[Dict] = []
    
    # Suspicious granted access masks for LSASS
    suspicious_access = {'0x1410', '0x1010', '0x1438', '0x143a', '0x1418'}
    
    # Required DLLs in call trace
    required_dlls = {
        'c:\\\\windows\\\\system32\\\\ntdll.dll',
        'c:\\\\windows\\\\system32\\\\kernelbase.dll'
    }

    for record in records:
        try:
            system_data = record["data"]["win"]["system"]
            event_data = record["data"]["win"]["eventdata"]
            
            # Check basic conditions first
            if (system_data["channel"] != "Microsoft-Windows-Sysmon/Operational" or
                system_data["eventID"] != "10" or
                event_data["targetImage"].lower() != "c:\\\\windows\\\\system32\\\\lsass.exe"):
                continue

            # Check granted access mask
            granted_access = event_data["grantedAccess"].lower()
            if granted_access not in suspicious_access:
                continue

            # Check call trace for required DLLs
            call_trace = event_data.get("callTrace", "").lower()
            if not all(dll in call_trace for dll in required_dlls):
                continue

            # If all conditions are met, add to results
            results.append(record)

        except Exception as e:
            # Log the error if needed
            continue

    return results