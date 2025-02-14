import csv
import json
from datetime import datetime

def convert_csv_to_es_bulk(csv_file, output_file, index_name="my_index"):
    # Read the CSV headers
    with open(csv_file, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        headers = reader.fieldnames
        
        # Open output file for writing bulk format
        with open(output_file, 'w', encoding='utf-8') as out_f:
            # Process each row
            for row in reader:
                entry = {}
                
                # Process each field in the row
                for field in headers:
                    if field.startswith('_'):  # Skip fields starting with underscore
                        continue
                        
                    # Split the field name by dots to create nested structure
                    parts = field.split('.')
                    current = entry
                    
                    # Create nested structure
                    for i, part in enumerate(parts[:-1]):
                        if part not in current:
                            current[part] = {}
                        current = current[part]
                    
                    # Set the value for the last part
                    if row[field]:  # Only add non-empty values
                        # Try to convert numeric strings to numbers
                        value = row[field]
                        try:
                            if '.' in value:
                                value = float(value)
                            else:
                                value = int(value)
                        except ValueError:
                            pass
                        
                        current[parts[-1]] = value

                # Create the action metadata
                action = {
                    "index": {
                        "_index": index_name,
                        "_id": row.get('id', None)  # Use 'id' field if exists, else Elasticsearch will generate one
                    }
                }
                
                # Write the action and document lines
                # Each line must end with a newline, including the last line
                out_f.write(json.dumps(action) + '\n')
                out_f.write(json.dumps(entry) + '\n')

def main():
    input_file = 'csv/full_log.csv'
    output_file = 'csv/full_log_es_bulk_import.json'
    index_name = 'wazuh-alerts-*'  # Change this to your desired index name
    
    try:
        convert_csv_to_es_bulk(input_file, output_file, index_name)
        print(f"Successfully converted CSV to Elasticsearch bulk format")
        print(f"Output saved to {output_file}")
        print("\nTo import to Elasticsearch, use the following curl command:")
        print(f"curl -H 'Content-Type: application/x-ndjson' -XPOST 'localhost:9200/_bulk' --data-binary '@{output_file}'")
    except Exception as e:
        print(f"Error: {str(e)}")

if __name__ == "__main__":
    main()