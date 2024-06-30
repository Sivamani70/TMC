[CmdletBinding()]
param (
    [Parameter(Mandatory)]
    [string[]] $WorkBooks
)


class TMCXLGenerator {

    [hashtable] $IOCs
    [string[]] $WorkBooks
    
    [int16] $MD5Count = 0
    [int16] $SHA1Count = 0
    [int16] $SHA256Count = 0
    [int16] $DomainsCount = 0
    [int16] $URLsCount = 0
    [int16] $EmailsCount = 0
    [int16] $IPCount = 0
    [int16] $OtherCount = 0
    [int16] $Total = 0
    
    [System.Collections.Generic.HashSet[String]] $MD5
    [System.Collections.Generic.HashSet[String]] $SHA1
    [System.Collections.Generic.HashSet[String]] $SHA256
    [System.Collections.Generic.HashSet[String]] $Domains
    [System.Collections.Generic.HashSet[String]] $URLS
    [System.Collections.Generic.HashSet[String]] $IPS
    [System.Collections.Generic.HashSet[String]] $Emails
    [System.Collections.Generic.HashSet[String]] $OtherIOCs

    [String] $MD5_Validator = "^[a-fA-F0-9]{32}$"
    [String] $SHA1_Validator = "^[a-fA-F0-9]{40}$"
    [String] $SHA256_Validator = "^[a-fA-F0-9]{64}$"
    [String] $DomainValidator = "^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})?$"   
    [String] $URLValidator = "^(https?|hxxps?|ftp):\/\/[^\s/$.?#].[^\s]*$"
    [String] $EmailValidator = "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    [String] $IPV4Validator = "^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    [String] $IPV6Validator = "^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$"

    TMCXLGenerator([string[]] $Files) {
        Clear-Host
        $this.WorkBooks = $Files
        $this.IOCs = @{};

        $this.MD5 = New-Object System.Collections.Generic.HashSet[String]
        $this.SHA1 = New-Object System.Collections.Generic.HashSet[String]
        $this.SHA256 = New-Object System.Collections.Generic.HashSet[String]
        $this.Domains = New-Object System.Collections.Generic.HashSet[String]
        $this.URLS = New-Object System.Collections.Generic.HashSet[String]
        $this.IPS = New-Object System.Collections.Generic.HashSet[String]
        $this.Emails = New-Object System.Collections.Generic.HashSet[String]
        $this.OtherIOCs = New-Object System.Collections.Generic.HashSet[String]
    }

    [String] GetFileName() {
        [datetime] $Date = Get-Date
        [string] $Month = (Get-Culture).DateTimeFormat.GetMonthName($Date.Month)
        return "TMC Threat Bytes $Month $($Date.Day) $($Date.Year)"
    }

    [void] ClearAllLists() {
        $this.MD5.Clear()
        $this.SHA1.Clear()
        $this.SHA256.Clear()
        $this.Domains.Clear()
        $this.URLS.Clear()
        $this.Emails.Clear()
        $this.IPS.Clear()
        $this.OtherIOCs.Clear()
    }

    [Void] UpdateCount() {
        $this.MD5Count += $this.MD5.Count
        $this.SHA1Count += $this.SHA1.Count
        $this.SHA256Count += $this.SHA256.Count
        $this.DomainsCount += $this.Domains.Count
        $this.URLsCount += $this.URLS.Count
        $this.EmailsCount += $this.Emails.Count
        $this.IPCount += $this.IPS.Count
        $this.OtherCount += $this.OtherIOCs.Count

        $this.Total = $this.MD5Count + $this.SHA1Count + $this.SHA256Count + $this. DomainsCount + $this.URLsCount + $this.EmailsCount + $this.IPCount + $this.OtherCount
    }

    [Void] IPExtractorFromURLs([string]$Indicator) {
        [string] $ipLookup = "(https?|hxxps?|ftp)://(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
        if ($Indicator -match $ipLookup) {
            foreach ($value in $Matches.Values) {
                if ($value -match $this.IPV4Validator) {
                    $this.IPS.Add($value) | Out-Null
                }
            }
        }
    }

    [void] Seperator([System.Collections.Generic.List[String]] $Indicators) {
        foreach ($Indicator in $Indicators) {
            $Indicator = ($Indicator.ToLower()).Trim()

            # Removing Sanitization 
            if ($Indicator.Contains("[:]")) {
                $Indicator = $Indicator.Replace("[:]", ":")
            }
    
            if ($Indicator.Contains("[://]")) {
                $Indicator = $Indicator.Replace("[://]", "://")
            }

            if ($Indicator.Contains("[.]")) {
                $Indicator = $Indicator.Replace("[.]", ".")
            }

            if ($Indicator -match $this.IPV4Validator -or $Indicator -match $this.IPV6Validator) {
                $this.IPS.Add($Indicator) | Out-Null
                continue;
            }
    
            if ($Indicator -match $this.DomainValidator) {
                $this.Domains.Add($Indicator) | Out-Null
                continue;
            }
    
            if ($Indicator -match $this.MD5_Validator) {
                $this.MD5.Add($Indicator) | Out-Null
                continue;
            }
    
            if ($Indicator -match $this.SHA1_Validator) {
                $this.SHA1.Add($Indicator) | Out-Null
                continue;
            }
    
            if ($Indicator -match $this.SHA256_Validator) {
                $this.SHA256.Add($Indicator) | Out-Null
                continue;
            }
    
            if ($Indicator -match $this.URLValidator) {
                $this.URLS.Add($Indicator) | Out-Null
                $this.IPExtractorFromURLs($Indicator)
                continue;
            }

            if (
                $Indicator -eq 'hashes' -or `
                    $Indicator -eq 'hash' -or `
                    $Indicator -eq 'domain' -or `
                    $Indicator -eq 'url' -or `
                    $Indicator -eq 'urls' -or `
                    $Indicator -eq 'email' -or `
                    $Indicator -eq 'emails' -or `
                    $Indicator -eq 'ip address'

            ) {
                continue;
            }
            $this.OtherIOCs.Add($Indicator) | Out-Null

        }
    }

    #1. Go through Multiple Files
    [void] Iterator() {
        $Counter = 0
        foreach ($WorkBook in $this.WorkBooks) {
            if ($this.IsValidPath($WorkBook)) {
                $MalwareName = ((Split-Path -Path $WorkBook -Leaf).Split('.')[0]).Replace(':', '')
                $this.ReadandExtractValues($MalwareName, $WorkBook)
                $Counter++
            }
            else {
                Write-Warning "File not exist -- [$WorkBook]"
            }
        }
        if ($Counter) {
            $this.CreateTMCWorkBook()
        }
    }

    #2. Validate File-Path
    [bool] IsValidPath([string] $Path) {
        return Test-Path -Path $Path
    }

    # 3. Read Values from Files and Add to Collection {HashTable}
    [void] ReadandExtractValues([string] $MalwareName, [string] $WorkBookPath) {
        $ListOfIOCs = New-Object System.Collections.Generic.HashSet[String]
        $Names = New-Object System.Collections.Generic.List[String]
        $Excel = New-Object -ComObject Excel.Application
        $WorkBook = $Excel.Workbooks.Open($WorkBookPath)

        Write-Host "Extracting IOCs from the WorkBook: [$WorkBookPath]"  -ForegroundColor Green

        try {
            foreach ($Sheet in $WorkBook.Sheets) {
                $Names.Add($Sheet.Name)
            }

            foreach ($Name in $Names) {
                if ($Name.ToLower() -eq "Techniques and Tactics".ToLower()) { 
                    Write-Warning "Skipping the Sheet -- [$Name]"   
                    continue; 
                }
                $WorkSheet = $WorkBook.Sheets[$Name]
                Write-Host "Extracting IOCs from the Sheet: [$Name]"  -ForegroundColor Green
                $RowsCount = ($WorkSheet.UsedRange.Rows).Count + 1
                $ColsCount = ($WorkSheet.UsedRange.Columns).Count + 1

                foreach ($R in 1..$RowsCount) {
                    foreach ($C in 1..$ColsCount) {
                        $Value = $WorkSheet.Cells.Item($R, $C).Text
                        if ($Value -ne "") {
                            $ListOfIOCs.Add($Value) | Out-Null
                        }
                    }
                }
 
            }

            $this.IOCs.Add($MalwareName, $ListOfIOCs)
        }
        finally {
            $Workbook.Close()
            $Excel.Quit()
            $ExitCode = [System.Runtime.InteropServices.Marshal]::ReleaseComObject($Excel) 
            Write-Host "Closing the File:[$WorkBookPath] with Exit-Code: $ExitCode" -ForegroundColor Yellow
        }

    }

    [string] ReName([string] $OriginalName, [string] $Delimiter) {
        return ($OriginalName.Replace($Delimiter, " ")).Trim()
    }

    # 4. Create TMC Sheet
    [Void] CreateTMCWorkBook() {
        [String] $FileName = $this.GetFileName()
        $PathWithFileName = (Get-Location).Path + "\$FileName.xlsx"
        $Excel = New-Object -ComObject Excel.Application 

        try {
            $WorkBook = $Excel.Workbooks.Add()
            Write-Host "Creating File -- $PathWithFileName. `nThis may take some time...." -ForegroundColor Green
            foreach ($MalwareName in $this.IOCs.Keys) {
                $this.ClearAllLists()
                Write-Host "Adding IOCs to Sheet: [$MalwareName]" -ForegroundColor Green
                $WorkSheet = $WorkBook.Worksheets.Add()
                $SheetName = $MalwareName
                
                [string[]] $Delimiters = @('\', '/', '?', '*', '[', ']', '(', ')', "'")
                foreach ($Delimiter in $Delimiters) {
                    $SheetName = $this.ReName($SheetName, $Delimiter)
                }

                if ($SheetName.Length -ge 30) {
                    $SheetName = $SheetName.Substring(0, 29)
                }

                Write-Warning "Sheet Name: $SheetName"
                $WorkSheet.Name = $SheetName
                $Indicators = $this.IOCs[$MalwareName]
                $this.Seperator($Indicators)

                # Adding Data to Sheets
                $Col = 0
                if ($this.MD5.Count -ne 0) {
                    $Row = 2
                    $Col += 2
                    $Cell = $workSheet.Cells[$row, $col]
                    $Cell.Value = "MD5"
                    $Cell.Interior.ColorIndex = 37
                    $Cell.Borders.LineStyle = 1
                    $Cell.Borders.ColorIndex = 1
                    $Cell.HorizontalAlignment = 3
                    foreach ($Hash in $this.MD5) {
                        $Row++
                        $Cell = $workSheet.Cells[$row, $col]
                        $Cell.Value = $Hash
                        $Cell.Borders.LineStyle = 1
                        $Cell.Borders.ColorIndex = 1
                    }
                }

                if ($this.SHA1.Count -ne 0) {
                    $Row = 2
                    $Col += 2
                    $Cell = $workSheet.Cells[$row, $col]
                    $Cell.Value = "SHA1"
                    $Cell.Interior.ColorIndex = 37
                    $Cell.Borders.LineStyle = 1
                    $Cell.Borders.ColorIndex = 1
                    $Cell.HorizontalAlignment = 3
                    foreach ($Hash in $this.SHA1) {
                        $Row++
                        $Cell = $workSheet.Cells[$row, $col]
                        $Cell.Value = $Hash
                        $Cell.Borders.LineStyle = 1
                        $Cell.Borders.ColorIndex = 1
                    }
                }

                if ($this.SHA256.Count -ne 0) {
                    $Row = 2
                    $Col += 2
                    $Cell = $workSheet.Cells[$row, $col]
                    $Cell.Value = "SHA256"
                    $Cell.Interior.ColorIndex = 37
                    $Cell.Borders.LineStyle = 1
                    $Cell.Borders.ColorIndex = 1
                    $Cell.HorizontalAlignment = 3
                    foreach ($Hash in $this.SHA256) {
                        $Row++
                        $Cell = $workSheet.Cells[$row, $col]
                        $Cell.Value = $Hash
                        $Cell.Borders.LineStyle = 1
                        $Cell.Borders.ColorIndex = 1
                    }
                }

                if ($this.Domains.Count -ne 0) {
                    $Row = 2
                    $Col += 2
                    $Cell = $workSheet.Cells[$row, $col]
                    $Cell.Value = "Domains"
                    $Cell.Interior.ColorIndex = 37
                    $Cell.Borders.LineStyle = 1
                    $Cell.Borders.ColorIndex = 1
                    $Cell.HorizontalAlignment = 3
                    foreach ($Domain in $this.Domains) {
                        $Row++
                        $Cell = $workSheet.Cells[$row, $col]
                        $Cell.Value = $Domain
                        $Cell.Borders.LineStyle = 1
                        $Cell.Borders.ColorIndex = 1
                    }
                }

                if ($this.URLS.Count -ne 0) {
                    $Row = 2
                    $Col += 2
                    $Cell = $workSheet.Cells[$row, $col]
                    $Cell.Value = "URLs"
                    $Cell.Interior.ColorIndex = 37
                    $Cell.Borders.LineStyle = 1
                    $Cell.Borders.ColorIndex = 1
                    $Cell.HorizontalAlignment = 3
                    foreach ($URL in $this.URLS) {
                        $Row++
                        $Cell = $workSheet.Cells[$row, $col]
                        $Cell.Value = $URL
                        $Cell.Borders.LineStyle = 1
                        $Cell.Borders.ColorIndex = 1
                    }
                }

                if ($this.Emails.Count -ne 0) {
                    $Row = 2
                    $Col += 2
                    $Cell = $workSheet.Cells[$row, $col]
                    $Cell.Value = "Emails"
                    $Cell.Interior.ColorIndex = 37
                    $Cell.Borders.LineStyle = 1
                    $Cell.Borders.ColorIndex = 1
                    $Cell.HorizontalAlignment = 3
                    foreach ($Email in $this.Emails) {
                        $Row++
                        $Cell = $workSheet.Cells[$row, $col]
                        $Cell.Value = $Email
                        $Cell.Borders.LineStyle = 1
                        $Cell.Borders.ColorIndex = 1
                    }
                }

                if ($this.IPS.Count -ne 0) {
                    $Row = 2
                    $Col += 2
                    $Cell = $workSheet.Cells[$row, $col]
                    $Cell.Value = "IP"
                    $Cell.Interior.ColorIndex = 37
                    $Cell.Borders.LineStyle = 1
                    $Cell.Borders.ColorIndex = 1
                    $Cell.HorizontalAlignment = 3
                    foreach ($Ip in $this.IPS) {
                        $Row++
                        $Cell = $workSheet.Cells[$row, $col]
                        $Cell.Value = $Ip
                        $Cell.Borders.LineStyle = 1
                        $Cell.Borders.ColorIndex = 1
                    }
                }

                if ($this.OtherIOCs.Count -ne 0) {
                    $Row = 2
                    $Col += 2
                    $Cell = $workSheet.Cells[$row, $col]
                    $Cell.Value = "Review -- Below Values"
                    $Cell.Interior.ColorIndex = 37
                    $Cell.Borders.LineStyle = 1
                    $Cell.Borders.ColorIndex = 1
                    $Cell.HorizontalAlignment = 3
                    foreach ($OtherIoc in $this.OtherIOCs) {
                        $Row++
                        $Cell = $workSheet.Cells[$row, $col]
                        $Cell.Value = $OtherIoc
                        $Cell.Borders.LineStyle = 1
                        $Cell.Borders.ColorIndex = 1
                    }
                }

                $WorkSheet.Columns("A:Z").AutoFit()
                $this.UpdateCount()
            }

            $CountSheet = $WorkBook.Sheets["Sheet1"]
            $CountSheet.Name = "Count"
            $Row = 2
            $NameCol = 2
            $NameCell = $CountSheet.Cells[$Row, $NameCol] 
            $NameCell.Value = "IOC Type"
            $NameCell.Borders.LineStyle = 1
            $NameCell.Borders.ColorIndex = 1
            $NameCell.Interior.ColorIndex = 37 
            $NameCell.HorizontalAlignment = 2

            $CountCol = 3
            $CountCell = $CountSheet.Cells[$Row, $CountCol]
            $CountCell.Value = "Count"
            $CountCell.Borders.LineStyle = 1
            $CountCell.Borders.ColorIndex = 1
            $CountCell.Interior.ColorIndex = 37 
            $CountCell.HorizontalAlignment = 3

            if ($this.MD5Count -ne 0) {
                $Row += 1
                $NameCell = $CountSheet.Cells[$Row, $NameCol]  
                $NameCell.Value = "MD5"
                $NameCell.Borders.LineStyle = 1
                $NameCell.Borders.ColorIndex = 1
                $NameCell.HorizontalAlignment = 2

                $CountCell = $CountSheet.Cells[$Row, $CountCol]
                $CountCell.Value = "$($this.MD5Count)"
                $CountCell.Borders.LineStyle = 1
                $CountCell.Borders.ColorIndex = 1
                $CountCell.HorizontalAlignment = 3
            }

            if ($this.SHA1Count -ne 0) {
                $Row += 1
                $NameCell = $CountSheet.Cells[$Row, $NameCol]  
                $NameCell.Value = "SHA1"
                $NameCell.Borders.LineStyle = 1
                $NameCell.Borders.ColorIndex = 1
                $NameCell.HorizontalAlignment = 2

                $CountCell = $CountSheet.Cells[$Row, $CountCol]
                $CountCell.Value = "$($this.SHA1Count)"
                $CountCell.Borders.LineStyle = 1
                $CountCell.Borders.ColorIndex = 1
                $CountCell.HorizontalAlignment = 3
            }

            if ($this.SHA256Count -ne 0) {
                $Row += 1
                $NameCell = $CountSheet.Cells[$Row, $NameCol]  
                $NameCell.Value = "SHA256"
                $NameCell.Borders.LineStyle = 1
                $NameCell.Borders.ColorIndex = 1
                $NameCell.HorizontalAlignment = 2

                $CountCell = $CountSheet.Cells[$Row, $CountCol]
                $CountCell.Value = "$($this.SHA256Count)"
                $CountCell.Borders.LineStyle = 1
                $CountCell.Borders.ColorIndex = 1
                $CountCell.HorizontalAlignment = 3
            }

            if ($this.DomainsCount -ne 0) {
                $Row += 1
                $NameCell = $CountSheet.Cells[$Row, $NameCol]  
                $NameCell.Value = "Domains"
                $NameCell.Borders.LineStyle = 1
                $NameCell.Borders.ColorIndex = 1
                $NameCell.HorizontalAlignment = 2

                $CountCell = $CountSheet.Cells[$Row, $CountCol]
                $CountCell.Value = "$($this.DomainsCount)"
                $CountCell.Borders.LineStyle = 1
                $CountCell.Borders.ColorIndex = 1
                $CountCell.HorizontalAlignment = 3
            }

            if ($this.URLsCount -ne 0) {
                $Row += 1
                $NameCell = $CountSheet.Cells[$Row, $NameCol]  
                $NameCell.Value = "URLs"
                $NameCell.Borders.LineStyle = 1
                $NameCell.Borders.ColorIndex = 1
                $NameCell.HorizontalAlignment = 2

                $CountCell = $CountSheet.Cells[$Row, $CountCol]
                $CountCell.Value = "$($this.URLsCount)"
                $CountCell.Borders.LineStyle = 1
                $CountCell.Borders.ColorIndex = 1
                $CountCell.HorizontalAlignment = 3
            }

            if ($this.EmailsCount -ne 0) {
                $Row += 1
                $NameCell = $CountSheet.Cells[$Row, $NameCol]  
                $NameCell.Value = "Emails"
                $NameCell.Borders.LineStyle = 1
                $NameCell.Borders.ColorIndex = 1
                $NameCell.HorizontalAlignment = 2

                $CountCell = $CountSheet.Cells[$Row, $CountCol]
                $CountCell.Value = "$($this.EmailsCount)"
                $CountCell.Borders.LineStyle = 1
                $CountCell.Borders.ColorIndex = 1
                $CountCell.HorizontalAlignment = 3
            }

            if ($this.IPCount -ne 0) {
                $Row += 1
                $NameCell = $CountSheet.Cells[$Row, $NameCol]  
                $NameCell.Value = "IP"
                $NameCell.Borders.LineStyle = 1
                $NameCell.Borders.ColorIndex = 1
                $NameCell.HorizontalAlignment = 2

                $CountCell = $CountSheet.Cells[$Row, $CountCol]
                $CountCell.Value = "$($this.IPCount)"
                $CountCell.Borders.LineStyle = 1
                $CountCell.Borders.ColorIndex = 1
                $CountCell.HorizontalAlignment = 3
            }

            if ($this.OtherCount -ne 0) {
                $Row += 1
                $NameCell = $CountSheet.Cells[$Row, $NameCol]  
                $NameCell.Value = "Review - IOCs"
                $NameCell.Borders.LineStyle = 1
                $NameCell.Borders.ColorIndex = 1
                $NameCell.HorizontalAlignment = 2

                $CountCell = $CountSheet.Cells[$Row, $CountCol]
                $CountCell.Value = "$($this.OtherCount)"
                $CountCell.Borders.LineStyle = 1
                $CountCell.Borders.ColorIndex = 1
                $CountCell.HorizontalAlignment = 3
            }

            $Row += 1
            $NameCell = $CountSheet.Cells[$Row, $NameCol]  
            $NameCell.Value = "Total"
            $NameCell.Borders.LineStyle = 1
            $NameCell.Borders.ColorIndex = 1
            $NameCell.HorizontalAlignment = 2
            $NameCell.Interior.ColorIndex = 37 

            $CountCell = $CountSheet.Cells[$Row, $CountCol]
            $CountCell.Value = "$($this.Total)"
            $CountCell.Borders.LineStyle = 1
            $CountCell.Borders.ColorIndex = 1
            $CountCell.HorizontalAlignment = 3

            Write-Host "Saving & Closing the WorkBook" -ForegroundColor Green
            $WorkBook.SaveAs($PathWithFileName)
            $WorkBook.Close()
        }
        finally {
            $Excel.Quit()
            $ExitCode = [System.Runtime.InteropServices.Marshal]::ReleaseComObject($excel) 
            Write-Host "Closing the File: [$PathWithFileName] with Exit-Code: $ExitCode" -ForegroundColor Yellow
        }
    }

}

#Script execution Starts from here. 
if ((Test-Path -Path "HKLM:\SOFTWARE\Microsoft\Office\*\Excel")) {
    [TMCXLGenerator] $TMC = [TMCXLGenerator]::new($WorkBooks)
    $TMC.Iterator()
}
else {
    Write-Error "No Excel Module found in the System"
}
