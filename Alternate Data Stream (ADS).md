# Command
PS> ```Get-Content <filename> -Stream Zone.Identifier```

## Output:
  
```
[ZoneTransfer]
ZoneId=3
ReferrerUrl=http://10.10.10.245/data/0
HostUrl=http://10.10.10.245/download/0
```

### ZoneID

1 = Local_Machine

2 = Intranet

3 = Internet

### ReferrerURL

Where the HostUrl is referred from

### HostUrl

Where the file is downloaded from
