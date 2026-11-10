// VAJRA — Azure Infrastructure-as-Code (Prompt 0048)
// Target: Azure App Service (Linux, Node 22 LTS) + Azure Database for PostgreSQL Flexible Server (Private VNet)
//         + Azure Key Vault (RBAC + Managed Identity) + Application Insights & Azure Monitor Alerts.
// NOTE: Template prepared for cloud readiness only. Do NOT deploy without explicit cost & environment approval.

targetScope = 'resourceGroup'

@description('Short prefix for VAJRA cloud resources (lowercase alphanumeric, 3-12 chars).')
@minLength(3)
@maxLength(12)
param namePrefix string = 'vajra'

@description('Deployment environment label.')
@allowed([
  'staging'
  'production'
])
param environmentName string = 'production'

@description('Primary Azure region for all resources.')
param location string = resourceGroup().location

@description('App Service Linux SKU (B1 for small/academic validation; P1v3 for production HA).')
@allowed([
  'B1'
  'B2'
  'P1v3'
])
param appServiceSkuName string = 'B1'

@description('PostgreSQL Flexible Server SKU name.')
param postgresSkuName string = 'Standard_B1ms'

@description('PostgreSQL Flexible Server compute tier.')
@allowed([
  'Burstable'
  'GeneralPurpose'
])
param postgresSkuTier string = 'Burstable'

@description('PostgreSQL Flexible Server storage size in GiB.')
@minValue(32)
@maxValue(1024)
param postgresStorageSizeGB int = 32

@description('PostgreSQL backup retention days (7-35).')
@minValue(7)
@maxValue(35)
param postgresBackupRetentionDays int = 14

@description('Enable geo-redundant backups on PostgreSQL Flexible Server.')
param postgresGeoRedundantBackup bool = false

@description('PostgreSQL administrator login (use a dedicated app role for runtime DML after migration).')
param postgresAdminLogin string = 'vajra_pgadmin'

@secure()
@description('PostgreSQL administrator password (supplied securely at deployment time; never stored in files).')
param postgresAdminPassword string

@secure()
@description('Runtime DATABASE_URL stored in Key Vault (uses least-privilege app role + sslmode=require).')
param runtimeDatabaseUrl string

@secure()
@description('High-entropy >=32 char SESSION_SECRET stored in Key Vault.')
param sessionSecret string

@secure()
@description('Distinct high-entropy >=32 char TOTP_ENCRYPTION_KEY stored in Key Vault.')
param totpEncryptionKey string

@description('Optional custom HTTPS origin (defaults to https://<webAppName>.azurewebsites.net when empty).')
param customPublicOrigin string = ''

var uniqueSuffix = uniqueString(resourceGroup().id, namePrefix, environmentName)
var vnetName = '${namePrefix}-${environmentName}-vnet'
var appSubnetName = 'snet-appservice'
var pgSubnetName = 'snet-postgres'
var privateDnsZoneName = '${namePrefix}-${environmentName}.private.postgres.database.azure.com'
var logAnalyticsName = '${namePrefix}-${environmentName}-law-${take(uniqueSuffix, 6)}'
var appInsightsName = '${namePrefix}-${environmentName}-ai-${take(uniqueSuffix, 6)}'
var keyVaultName = take('${namePrefix}${environmentName}kv${uniqueSuffix}', 24)
var pgServerName = '${namePrefix}-${environmentName}-pg-${take(uniqueSuffix, 6)}'
var appPlanName = '${namePrefix}-${environmentName}-plan'
var webAppName = '${namePrefix}-${environmentName}-web-${take(uniqueSuffix, 6)}'
var canonicalPublicOrigin = empty(customPublicOrigin)
  ? 'https://${webAppName}.azurewebsites.net'
  : customPublicOrigin

// Built-in Azure RBAC role: Key Vault Secrets User
var keyVaultSecretsUserRoleId = subscriptionResourceId(
  'Microsoft.Authorization/roleDefinitions',
  '4633458b-17de-408a-b874-0445c86b69e6'
)

resource logAnalytics 'Microsoft.OperationalInsights/workspaces@2022-10-01' = {
  name: logAnalyticsName
  location: location
  properties: {
    sku: {
      name: 'PerGB2018'
    }
    retentionInDays: 30
  }
}

resource appInsights 'Microsoft.Insights/components@2020-02-02' = {
  name: appInsightsName
  location: location
  kind: 'web'
  properties: {
    Application_Type: 'web'
    WorkspaceResourceId: logAnalytics.id
    IngestionMode: 'LogAnalytics'
    publicNetworkAccessForIngestion: 'Enabled'
    publicNetworkAccessForQuery: 'Enabled'
  }
}

resource vnet 'Microsoft.Network/virtualNetworks@2023-09-01' = {
  name: vnetName
  location: location
  properties: {
    addressSpace: {
      addressPrefixes: [
        '10.20.0.0/16'
      ]
    }
    subnets: [
      {
        name: appSubnetName
        properties: {
          addressPrefix: '10.20.1.0/24'
          delegations: [
            {
              name: 'delegation-appservice'
              properties: {
                serviceName: 'Microsoft.Web/serverFarms'
              }
            }
          ]
        }
      }
      {
        name: pgSubnetName
        properties: {
          addressPrefix: '10.20.2.0/24'
          delegations: [
            {
              name: 'delegation-postgres-flexible'
              properties: {
                serviceName: 'Microsoft.DBforPostgreSQL/flexibleServers'
              }
            }
          ]
        }
      }
    ]
  }
}

resource privateDnsZone 'Microsoft.Network/privateDnsZones@2020-06-01' = {
  name: privateDnsZoneName
  location: 'global'
}

resource privateDnsZoneLink 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2020-06-01' = {
  parent: privateDnsZone
  name: '${vnetName}-link'
  location: 'global'
  properties: {
    registrationEnabled: false
    virtualNetwork: {
      id: vnet.id
    }
  }
}

resource postgresServer 'Microsoft.DBforPostgreSQL/flexibleServers@2023-06-01-preview' = {
  name: pgServerName
  location: location
  sku: {
    name: postgresSkuName
    tier: postgresSkuTier
  }
  properties: {
    version: '15'
    administratorLogin: postgresAdminLogin
    administratorLoginPassword: postgresAdminPassword
    storage: {
      storageSizeGB: postgresStorageSizeGB
      autoGrow: 'Enabled'
    }
    backup: {
      backupRetentionDays: postgresBackupRetentionDays
      geoRedundantBackup: postgresGeoRedundantBackup ? 'Enabled' : 'Disabled'
    }
    network: {
      delegatedSubnetResourceId: vnet.properties.subnets[1].id
      privateDnsZoneArmResourceId: privateDnsZone.id
    }
    highAvailability: {
      mode: 'Disabled'
    }
  }
  dependsOn: [
    privateDnsZoneLink
  ]
}

resource postgresRequireTls 'Microsoft.DBforPostgreSQL/flexibleServers/configurations@2023-06-01-preview' = {
  parent: postgresServer
  name: 'require_secure_transport'
  properties: {
    value: 'ON'
    source: 'user-override'
  }
}

resource postgresMinTlsVersion 'Microsoft.DBforPostgreSQL/flexibleServers/configurations@2023-06-01-preview' = {
  parent: postgresServer
  name: 'ssl_min_protocol_version'
  properties: {
    value: 'TLSv1.2'
    source: 'user-override'
  }
}

resource vajraDatabase 'Microsoft.DBforPostgreSQL/flexibleServers/databases@2023-06-01-preview' = {
  parent: postgresServer
  name: 'vajra'
  properties: {
    charset: 'UTF8'
    collation: 'en_US.utf8'
  }
}

resource keyVault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: keyVaultName
  location: location
  properties: {
    tenantId: subscription().tenantId
    enableRbacAuthorization: true
    enableSoftDelete: true
    softDeleteRetentionInDays: 90
    enablePurgeProtection: true
    sku: {
      family: 'A'
      name: 'standard'
    }
    publicNetworkAccess: 'Enabled'
  }
}

resource kvSecretDatabaseUrl 'Microsoft.KeyVault/vaults/secrets@2023-07-01' = {
  parent: keyVault
  name: 'vajra-database-url'
  properties: {
    value: runtimeDatabaseUrl
  }
}

resource kvSecretSession 'Microsoft.KeyVault/vaults/secrets@2023-07-01' = {
  parent: keyVault
  name: 'vajra-session-secret'
  properties: {
    value: sessionSecret
  }
}

resource kvSecretTotp 'Microsoft.KeyVault/vaults/secrets@2023-07-01' = {
  parent: keyVault
  name: 'vajra-totp-encryption-key'
  properties: {
    value: totpEncryptionKey
  }
}

resource appServicePlan 'Microsoft.Web/serverfarms@2023-01-01' = {
  name: appPlanName
  location: location
  kind: 'linux'
  sku: {
    name: appServiceSkuName
  }
  properties: {
    reserved: true
  }
}

resource webApp 'Microsoft.Web/sites@2023-01-01' = {
  name: webAppName
  location: location
  kind: 'app,linux'
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    serverFarmId: appServicePlan.id
    httpsOnly: true
    virtualNetworkSubnetId: vnet.properties.subnets[0].id
    vnetRouteAllEnabled: true
    siteConfig: {
      linuxFxVersion: 'NODE|22-lts'
      alwaysOn: true
      http20Enabled: true
      minTlsVersion: '1.2'
      ftpsState: 'Disabled'
      healthCheckPath: '/api/ready'
      appCommandLine: '/home/site/wwwroot/infrastructure/scripts/startup-app-service.sh'
      appSettings: [
        {
          name: 'NODE_ENV'
          value: 'production'
        }
        {
          name: 'APP_ENV'
          value: 'production'
        }
        {
          name: 'TRUST_PROXY'
          value: 'true'
        }
        {
          name: 'REQUIRE_MFA'
          value: 'true'
        }
        {
          name: 'REQUIRE_PUBLIC_ORIGIN'
          value: 'true'
        }
        {
          name: 'DATABASE_SSL_REQUIRED'
          value: 'true'
        }
        {
          name: 'VAJRA_ENABLE_DEMO_ENDPOINTS'
          value: 'false'
        }
        {
          name: 'APP_PUBLIC_ORIGIN'
          value: canonicalPublicOrigin
        }
        {
          name: 'DATABASE_URL'
          value: '@Microsoft.KeyVault(SecretUri=${kvSecretDatabaseUrl.properties.secretUri})'
        }
        {
          name: 'SESSION_SECRET'
          value: '@Microsoft.KeyVault(SecretUri=${kvSecretSession.properties.secretUri})'
        }
        {
          name: 'TOTP_ENCRYPTION_KEY'
          value: '@Microsoft.KeyVault(SecretUri=${kvSecretTotp.properties.secretUri})'
        }
        {
          name: 'APPLICATIONINSIGHTS_CONNECTION_STRING'
          value: appInsights.properties.ConnectionString
        }
      ]
    }
  }
}

resource webAppKeyVaultRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(keyVault.id, webApp.id, 'KeyVaultSecretsUser')
  scope: keyVault
  properties: {
    roleDefinitionId: keyVaultSecretsUserRoleId
    principalId: webApp.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

resource http5xxAlert 'Microsoft.Insights/metricAlerts@2018-03-01' = {
  name: '${webAppName}-http5xx-alert'
  location: 'global'
  properties: {
    description: 'Alert when VAJRA Web App returns > 5 HTTP 5xx responses within 5 minutes.'
    severity: 2
    enabled: true
    scopes: [
      webApp.id
    ]
    evaluationFrequency: 'PT1M'
    windowSize: 'PT5M'
    criteria: {
      'odata.type': 'Microsoft.Azure.Monitor.SingleResourceMultipleMetricCriteria'
      allOf: [
        {
          name: 'Http5xxThreshold'
          metricName: 'Http5xx'
          operator: 'GreaterThan'
          threshold: 5
          timeAggregation: 'Total'
          criterionType: 'StaticThresholdCriterion'
        }
      ]
    }
  }
}

resource healthCheckAlert 'Microsoft.Insights/metricAlerts@2018-03-01' = {
  name: '${webAppName}-readiness-alert'
  location: 'global'
  properties: {
    description: 'Alert when VAJRA /api/ready health check availability drops below 99%.'
    severity: 1
    enabled: true
    scopes: [
      webApp.id
    ]
    evaluationFrequency: 'PT1M'
    windowSize: 'PT5M'
    criteria: {
      'odata.type': 'Microsoft.Azure.Monitor.SingleResourceMultipleMetricCriteria'
      allOf: [
        {
          name: 'HealthCheckStatusThreshold'
          metricName: 'HealthCheckStatus'
          operator: 'LessThan'
          threshold: 99
          timeAggregation: 'Average'
          criterionType: 'StaticThresholdCriterion'
        }
      ]
    }
  }
}

resource postgresCpuAlert 'Microsoft.Insights/metricAlerts@2018-03-01' = {
  name: '${pgServerName}-cpu-alert'
  location: 'global'
  properties: {
    description: 'Alert when PostgreSQL Flexible Server CPU exceeds 85% over 15 minutes.'
    severity: 2
    enabled: true
    scopes: [
      postgresServer.id
    ]
    evaluationFrequency: 'PT5M'
    windowSize: 'PT15M'
    criteria: {
      'odata.type': 'Microsoft.Azure.Monitor.SingleResourceMultipleMetricCriteria'
      allOf: [
        {
          name: 'CpuPercentThreshold'
          metricName: 'cpu_percent'
          operator: 'GreaterThan'
          threshold: 85
          timeAggregation: 'Average'
          criterionType: 'StaticThresholdCriterion'
        }
      ]
    }
  }
}

output webAppName string = webApp.name
output webAppDefaultHostName string = webApp.properties.defaultHostName
output canonicalOrigin string = canonicalPublicOrigin
output postgresFqdn string = postgresServer.properties.fullyQualifiedDomainName
output keyVaultUri string = keyVault.properties.vaultUri
