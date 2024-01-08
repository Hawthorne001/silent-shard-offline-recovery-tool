# Silence Laboratories Snap Recovery Script

Script to recover the private keys from the Silence Laboratories Snap Backup. 
The snap backup contains the keyshare of the phone app and the encrypted keyshare of the Metamask Snap. The encryption is done by the Metamask Snap by deriving entropy from the mnemonic phrase. This script can be used to decrypt the data, combine the keyshares and recover the private keys of the MPC wallets.  

## Run the script

We need two files to run the script:
- Recovery phrase of the Metamask Wallet (where Snap is installed): Must be stored in `recovery_phrase.txt` in the project directory
- Backup file of the Snap: Must be stored in `backup.json` in the project directory


Once the files are in place, run the script with the following command:

```bash
npm run recover
```


