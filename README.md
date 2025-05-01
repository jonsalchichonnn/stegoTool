# stegoTool
A steganography system using images sent through social networks

# Prerequisites
- python 3
- Microsoft Visual C++ 14.0 or greater (Windows)

# Set up
## Linux
1. Clone the repo
2. Within the folder
    1. `python3 -m venv myenv`
    2. `source myenv/bin/activate`
    3. `pip install -r requirements.txt`
3. Execute the script: `python3 stego.py`

## Windows

1. Clone the repo
2. Open cmd or PowerShell within the folder
    1. Create the virtual environment: `python -m venv myenv`
    2. Activate the virtual environment:
    
        - If using **CMD**:
            `myenv\Scripts\activate.bat`
        
        - If using **PowerShell**:
            `.\myenv\Scripts\Activate.ps1`
        
        > **Note:** If PowerShell blocks the script, run the following command to allow script execution for the current session:
        >`Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`
        
    3. `pip install -r requirements.txt`
3. Execute the script: `python stego.py`
4. (Optional) When done, deactivate the virtual environment:

    `deactivate`