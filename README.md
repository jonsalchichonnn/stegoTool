# StegoTool

This program lets you hide secret data inside images using steganography.
It's specifically designed to ensure your hidden data survives being
uploaded to Reddit and other social media platforms.

## How it works
- Your secret data is first encrypted with strong AES-256 encryption
- The encrypted data is converted to binary (1s and 0s)
- The program slightly modifies the least significant bits (LSBs) of pixel color values in your cover image
- These tiny changes are invisible to the human eye but contain your data
- To extract data, you need both the modified image AND the password

## Key features
- Security: AES-256 encryption + random bit distribution
- File Support: Can hide ANY file type inside images
- File Recovery: Automatically preserves original filename and extension
- Reddit-Optimized: Special processing to survive Reddit's compression
- Redundancy: Optional multi-region encoding for extra durability

## Tips for best results
- Use PNG format for both cover and output images
- Larger cover images can store more data
- Choose complex passwords (mix of letters, numbers, symbols)
- When extracting files, make sure to save with the correct extension
- Enable 'Reddit optimization' when sharing on social media

## Supported file types
- Cover Images: PNG, JPG, BMP (PNG recommended)
- Hidden Data: ANY file type (text, images, documents, archives, etc.)
- Output: Always PNG (preserves hidden data better)

## Set up
### Prerequisites
- python 3
- Microsoft Visual C++ 14.0 or greater (Windows)

### Execution
#### LINUX
1. Clone the repo
2. Within the folder
   ```
   python3 -m venv myenv
   source myenv/bin/activate
   pip install -r requirements.txt
   ```
4. Execute the script
   ```
   python3 stego.py
   ```
#### WINDOWS
1. Clone the repo
2. Open cmd or PowerShell within the folder
    1. Create the virtual environment:
       ```
       python -m venv myenv
       ```
    3. Activate the virtual environment:
    
        - If using **CMD**:
          ```
          myenv\Scripts\activate.bat
          ```
        - If using **PowerShell**:
          ```
          .\myenv\Scripts\Activate.ps1
          ```
        > **Note:** If PowerShell blocks the script, run the following command to allow script execution for the current session:
       `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`
        > 
    4. Install requirements:
        ```
        pip install -r requirements.txt
        ```
3. Execute the script: `python stego.py`

(Optional) When done, deactivate the virtual environment:
```
deactivate
```
