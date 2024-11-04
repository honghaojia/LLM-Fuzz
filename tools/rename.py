import os
import shutil

def clear_target_folder(target_folder):
    for item in os.listdir(target_folder):
        item_path = os.path.join(target_folder, item)
        if os.path.isfile(item_path):
            os.remove(item_path)
        elif os.path.isdir(item_path):
            shutil.rmtree(item_path)

def main():
    source = "../source"  
    target = "../rename_contracts"  
    
    clear_target_folder(target)
    
    files = os.listdir(source)
    for file in files:
        if not file.endswith(".sol"):
            continue
        
        src_file_path = os.path.join(source, file)
        
        with open(src_file_path, 'r') as fh:
            lines = fh.readlines()
        
       
        contract_names = []
        
        for line in lines:
            if line.strip().startswith("contract"):
                parts = line.split()
                if len(parts) > 1:
                    contract_name = parts[1].strip()
                    if contract_name.endswith("{"):
                        contract_name = contract_name[:-1]
                    contract_names.append(contract_name)
        
        if contract_names:

            last_contract_name = contract_names[-1]
            new_filename = f"{last_contract_name}.sol"
        else:
            continue
        
        shutil.copyfile(src_file_path, os.path.join(target, new_filename))

if __name__ == '__main__':
    main()
