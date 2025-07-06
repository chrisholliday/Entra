# Automating the Entra App Secret Report

This guide provides the step-by-step instructions to configure the necessary Azure resources for running the `Get-EntraAppSecretReport.ps1` script in an automated, non-interactive fashion using Azure Automation.

## Step 1: Create an App Registration for Automation

First, you need a dedicated App Registration (Service Principal) in Entra ID that the script can use to authenticate securely without user interaction.

### 1.1. Create a Self-Signed Certificate

Run the following PowerShell commands on your local machine. This will create a certificate that the App Registration will use for authentication.

```powershell
# Create a certificate valid for 2 years
$cert = New-SelfSignedCertificate -Subject "CN=EntraReportAutomation" -CertStoreLocation "Cert:\CurrentUser\My" -KeyExportPolicy Exportable -KeySpec Signature -NotAfter (Get-Date).AddYears(2)

# --- IMPORTANT: Note this thumbprint for the script parameters later ---
$thumbprint = $cert.Thumbprint
Write-Host "Certificate Thumbprint: $thumbprint"

# Export the public key (.cer) to upload to the App Registration in Entra ID
Export-Certificate -Cert $cert -FilePath ".\EntraReportAutomation.cer"

# Export the private key (.pfx) to upload to Azure Automation
$password = ConvertTo-SecureString -String "Your-Strong-Password-Here!" -AsPlainText -Force
Export-PfxCertificate -Cert $cert -FilePath ".\EntraReportAutomation.pfx" -Password $password

Write-Host "Certificate files 'EntraReportAutomation.cer' and 'EntraReportAutomation.pfx' created in the current directory."
```

### 1.2. Create the App Registration in Entra ID

1.  In the Entra ID portal, navigate to **Identity > Applications > App registrations** and select **New registration**.
2.  Give it a descriptive name, such as `Entra Secret Report Automation`.
3.  Leave the other options as default and click **Register**.
4.  From the app's **Overview** page, copy the **Application (client) ID** and **Directory (tenant) ID**. You will need these for the script's parameters.

### 1.3. Upload the Certificate's Public Key

1.  In your new App Registration, go to the **Certificates & secrets** blade.
2.  Select the **Certificates** tab and click **Upload certificate**.
3.  Upload the `EntraReportAutomation.cer` file you created in step 1.1.

### 1.4. Grant API Permissions

1.  Go to the **API permissions** blade.
2.  Click **Add a permission** > **Microsoft Graph** > **Application permissions**.
3.  Search for and add the following permissions:
    *   `Application.Read.All`
    *   `Directory.Read.All`
    *   `Mail.Send` (This is required for the email functionality)
4.  After adding the permissions, click the **Grant admin consent for [Your Tenant]** button and confirm.

---

## Step 2: Set up Azure Automation

Now, you will configure an Azure Automation account to run the script on a schedule.

### 2.1. Create an Automation Account

1.  In the Azure portal, search for and create a new **Automation Account**. A system-assigned managed identity is not required for this setup.

### 2.2. Install Required PowerShell Modules

1.  In your new Automation Account, navigate to **Modules** (under `Shared Resources`).
2.  Click **Add a module** and use the gallery to find and add the following modules (select a runtime version of 5.1):
    *   `Microsoft.Graph.Authentication`
    *   `Microsoft.Graph.Applications`
    *   `Microsoft.Graph.Users` (This provides the `Send-MgUserMessage` cmdlet for emailing)

### 2.3. Upload the Private Key Certificate

1.  Navigate to **Certificates** (under `Shared Resources`).
2.  Click **Add a certificate**.
3.  Upload the `EntraReportAutomation.pfx` file you created in step 1.1, and enter the password you set for it.

### 2.4. Create and Configure the Runbook

1.  Navigate to **Runbooks** (under `Process Automation`) and click **Create a runbook**.
2.  Give it a name, such as `Run-EntraAppSecretReport`.
3.  Select **PowerShell** as the `Runbook type` and **5.1** for the `Runtime version`.
4.  Click **Create**.
5.  Paste the entire modified `Get-EntraAppSecretReport.ps1` script code into the editor.
6.  **Save** and then **Publish** the runbook.

### 2.5. Schedule the Runbook

1.  From the Runbook's overview page, click **Link to schedule**.
2.  Select **Add a schedule**, then **Create a new schedule**.
3.  Configure it to run weekly (or on your desired cadence).
4.  On the **Parameters and run settings** page that appears, fill in the values for the script:
    *   **AutomationRun**: `True`
    *   **TenantId**: Your Directory (tenant) ID from step 1.2.
    *   **AppId**: Your Application (client) ID from step 1.2.
    *   **CertificateThumbprint**: The thumbprint from the certificate you created in step 1.1.
    *   **OutFile**: `report.csv` (This will be created in a temporary directory on the automation worker).
    *   **MailTo**: `security.team@yourdomain.com` (or a comma-separated list of addresses).
    *   **MailFromUpn**: The UPN of a licensed mailbox the app has permission to send from (e.g., `automation.account@yourdomain.com`).

Once you click OK, the automation is fully configured and will run on the schedule you defined.

