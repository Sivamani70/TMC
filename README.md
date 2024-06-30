# TMC Automation - PowerShell Script

## Script Functionality

### Values Extraction from Given List of Excel files:

- Parses the given Excel files which was received from the TMC Team.
- Extract the values(IOCs) from all the sheets/WorkBooks and make them into a list of values(IOCs) under the respective Malware name.
- Skips the Techniques and Tactics sheet.
- Organizes the IOCs in the corresponding sheet with their respective Malware Names as the sheet name.
- Creates a new excel workbook with the file name in the format of TMC Threat Bytes Month Date Year.
- Saves the newly created workbook in the same location from where the script has been initiated for execution.
