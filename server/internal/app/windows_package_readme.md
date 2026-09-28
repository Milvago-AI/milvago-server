# Install the Milvago Windows agent

This ZIP contains `milvago-windows-installer.msi`, `milvago-windows-install.ps1`, and the organization-specific `milvago-provision.json`.

1. Extract all files into the same folder. Keep the ZIP and provisioning JSON accessible only to authorized administrators.
2. Open PowerShell **as Administrator** and change to the extracted folder.
3. Run this command:

   ```powershell
   .\milvago-windows-install.ps1 -MsiPath .\milvago-windows-installer.msi -ProvisionPath .\milvago-provision.json
   ```

Both paths are required. Running the script without them prompts for `MsiPath` and `ProvisionPath`. Opening the MSI by itself cannot enroll a new device because the organization key is kept in the JSON file. The script checks the MSI, stages the JSON securely, and waits for Windows Installer to finish. If installation fails, it displays the numeric exit code and the location of an administrator-only diagnostic log. Protect that log when sharing it with support. Device approval may still be required in the console. Delete the ZIP and extracted JSON when they are no longer needed.

## Installation en français

1. Extrayez tous les fichiers dans le même dossier protégé.
2. Ouvrez PowerShell **en tant qu’administrateur** dans ce dossier.
3. Exécutez la commande ci-dessus avec les deux paramètres `-MsiPath` et `-ProvisionPath`.

Si vous lancez le script sans paramètres, PowerShell demande ces deux chemins. L’ouverture du MSI seul ne peut pas inscrire le poste : la clé de l’organisation se trouve dans le JSON. Le script attend la fin de Windows Installer. En cas d’échec, il affiche le code de retour numérique et le chemin d’un journal de diagnostic accessible aux administrateurs ; protégez ce journal avant de le transmettre au support. Protégez puis supprimez le ZIP et le JSON extraits dès qu’ils ne sont plus nécessaires.
