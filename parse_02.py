import re
import sys

def parse_and_flatten_audit(input_file_path):
    """
    Parses a cleaned PostgreSQL audit log and flattens the output
    to group permissions by user/role under each table.
    """
    try:
        with open(input_file_path, 'r') as f:
            lines = f.readlines()
    except FileNotFoundError:
        print(f"Error: The file '{input_file_path}' was not found.")
        print("Please make sure the input file is in the same directory as the script.")
        sys.exit(1)

    current_table = None
    permissions_by_table = {}

    # Regular expression to capture the role, login status, inherited roles, and permissions
    permission_line_regex = re.compile(
        r"^(?P<role_user>.{26}) \|"
        r"\s*(?P<login>Yes|No)\s*\|"
        r"\s*(?P<inherited_from>.{28}) \|"
        r"\s*(?P<select>X|\s)\s*\|"
        r"\s*(?P<insert>X|\s)\s*\|"
        r"\s*(?P<update>X|\s)\s*\|"
        r"\s*(?P<delete>X|\s)\s*\|"
    )

    for line in lines:
        line = line.strip()
        if line.startswith('TABLE:'):
            # Found a new table, set it as the current context
            current_table = line.replace('TABLE:', '').strip()
            permissions_by_table[current_table] = []
        elif '|' in line and current_table and not line.startswith('ROLE / USER'):
            # This is a permission line for the current table
            match = permission_line_regex.match(line)
            if match:
                permissions_by_table[current_table].append(match.groupdict())

    # Now, format and print the flattened output
    for table, permissions in permissions_by_table.items():
        if not permissions:
            continue

        print("\n" + "="*80)
        print(f"Table: {table}")
        print("="*80)
        print(f"{'ROLE / USER':<27}{'LOGIN?':<9}{'INHERITED FROM':<30}{'SELECT':<8}{'INSERT':<8}{'UPDATE':<8}{'DELETE':<8}")
        print(f"{'-'*26:<27}{'-'*8:<9}{'-'*29:<30}{'-'*7:<8}{'-'*7:<8}{'-'*7:<8}{'-'*7:<8}")

        for perm in permissions:
            # Clean up whitespace from captured groups
            role_user = perm['role_user'].strip()
            login = perm['login'].strip()
            inherited_from = perm['inherited_from'].strip()

            s = 'X' if 'X' in perm['select'] else '-'
            i = 'X' if 'X' in perm['insert'] else '-'
            u = 'X' if 'X' in perm['update'] else '-'
            d = 'X' if 'X' in perm['delete'] else '-'

            print(f"{role_user:<27}{login:<9}{inherited_from:<30}{s:<8}{i:<8}{u:<8}{d:<8}")
        
    print("\nReport generation complete.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python parse_audit.py <input_file.txt>")
        sys.exit(1)
    
    input_file = sys.argv[1]
    parse_and_flatten_audit(input_file)
