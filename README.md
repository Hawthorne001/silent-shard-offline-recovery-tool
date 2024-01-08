# Silence Laboratories Snap Recovery Script

Script to recover the private keys from the Silence Laboratories Snap Backup. 

The script will export the private keys from the Snap Backup file and write them to a JSON file.


It needs:
- The Snap Backup file (backup stored in the cloud or locally)
- The Metamask Wallet's recovery phrase (must be the same as the one used to create the Snap accounts)


## Instructions

1. Clone the repository
2. Install dependencies with `npm install`
3. To run the script, ensure the following files are in the project directory:

   - `recovery_phrase.txt`: Contains the Metamask Wallet's recovery phrase.
   - `backup.json`: Holds the contents of the Snap backup file.
4. Once the files are in place, run the script with the following commmand `npm run recovery`

The script will write the exported private keys to `exported-keys.json`.


