# This one is trying to use bascic fuzzing to see if we can find secret matches in other
# tools that will find a token pattern in GHAS Secrets Scanning.
# Initial results don't find any matches over fuzz factor of 60. Below that it's just noise.
# This of course requires plain text secrets in your file for testing. You can't do this on hashes.

import csv
from fuzzywuzzy import fuzz

# Define GHAS patterns from https://docs.github.com/en/enterprise-cloud@latest/code-security/secret-scanning/secret-scanning-patterns#supported-secrets
ghas_patterns = [
    "adafruit_io_key", "adobe_client_secret", "adobe_device_token", "adobe_pac_token", "adobe_refresh_token",
    "adobe_service_token", "adobe_short_lived_access_token", "aiven_auth_token", "aiven_service_password", "alibaba_cloud_access_key_id",
    "alibaba_cloud_access_key_secret", "amazon_oauth_client_id", "amazon_oauth_client_secret", "aws_access_key_id", "aws_secret_access_key",
    "aws_session_token", "aws_temporary_access_key_id", "aws_secret_access_key", "anthropic_api_key", "asana_personal_access_token",
    "atlassian_api_token", "atlassian_jwt", "bitbucket_server_personal_access_token", "authress_service_client_access_key",
    "azure_active_directory_application_secret", "azure_batch_key_identifiable", "azure_cache_for_redis_access_key", "azure_container_registry_key_identifiable",
    "azure_cosmosdb_key_identifiable", "azure_devops_personal_access_token", "azure_function_key", "azure_ml_web_service_classic_identifiable_key", "azure_sas_token",
    "azure_search_admin_key", "azure_search_query_key", "azure_management_certificate", "azure_sql_connection_string", "azure_sql_password",
    "azure_storage_account_key", "baiducloud_api_accesskey", "beamer_api_key", "cds_canada_notify_api_key", "canva_connect_api_secret",
    "cashfree_api_key", "checkout_production_secret_key", "checkout_test_secret_key", "chief_tools_token", "clojars_deploy_token",
    "cratesio_api_token", "databricks_access_token", "datadog_api_key", "defined_networking_nebula_api_key", "devcycle_client_api_key",
    "devcycle_mobile_api_key", "devcycle_server_api_key", "digitalocean_oauth_token", "digitalocean_personal_access_token", "digitalocean_refresh_token",
    "digitalocean_system_token", "discord_api_token_v2", "discord_bot_token", "docker_personal_access_token", "doppler_audit_token",
    "doppler_cli_token", "doppler_personal_token", "doppler_scim_token", "doppler_service_token", "doppler_service_account_token",
    "dropbox_access_token", "dropbox_short_lived_access_token", "duffel_live_access_token", "duffel_test_access_token", "dynatrace_access_token",
    "dynatrace_internal_token", "easypost_production_api_key", "easypost_test_api_key", "ebay_production_client_id", "ebay_production_client_secret",
    "ebay_sandbox_client_id", "ebay_sandbox_client_secret", "fastly_api_token", "figma_pat", "finicity_app_key", "flutterwave_live_api_secret_key",
    "flutterwave_test_api_secret_key", "frameio_developer_token", "frameio_jwt", "fullstory_api_key", "github_app_installation_access_token", "github_oauth_access_token",
    "github_personal_access_token", "github_refresh_token", "github_ssh_private_key", "gitlab_access_token", "gocardless_live_access_token", "gocardless_sandbox_access_token",
    "google_cloud_storage_service_account_access_key_id", "google_cloud_storage_access_key_secret", "google_cloud_storage_user_access_key_id", "google_cloud_storage_access_key_secret",
    "google_oauth_access_token", "google_oauth_client_id", "google_oauth_client_secret", "google_oauth_refresh_token", "google_api_key", "google_cloud_private_key_id",
    "grafana_cloud_api_key", "grafana_cloud_api_token", "grafana_project_api_key", "grafana_project_service_account_token", "hashicorp_vault_batch_token",
    "hashicorp_vault_root_service_token", "hashicorp_vault_service_token", "hashicorp_vault_service_token", "terraform_api_token", "highnote_rk_live_key", "highnote_rk_test_key",
    "highnote_sk_live_key", "highnote_sk_test_key", "hop_bearer", "hop_pat", "hop_ptk", "hubspot_api_key", "hubspot_api_personal_access_key",
    "intercom_access_token", "ionic_personal_access_token", "ionic_refresh_token", "jd_cloud_access_key", "jfrog_platform_access_token", "jfrog_platform_api_key",
    "jfrog_platform_reference_token", "linear_api_key", "linear_oauth_access_token", "lob_live_api_key", "lob_test_api_key", "localstack_api_key",
    "logicmonitor_bearer_token", "logicmonitor_lmv1_access_key", "mailchimp_api_key", "mandrill_api", "mailgun_api_key", "mapbox_secret_access_token", "maxmind_license_key",
    "mercury_non_production_api_token", "mercury_production_api_token", "messagebird_api_key", "facebook_access_token", "midtrans_production_server_key", "midtrans_sandbox_server_key",
    "new_relic_insights_query_key", "new_relic_license_key", "new_relic_personal_api_key", "new_relic_rest_api_key", "notion_integration_token", "notion_oauth_client_secret",
    "npm_access_token", "nuget_api_key", "octopus_deploy_api_key", "oculus_very_tiny_encrypted_session", "onechronos_api_key", "onechronos_eb_api_key", "onechronos_eb_encryption_key",
    "onechronos_oauth_token", "onechronos_refresh_token", "onfido_live_api_token", "onfido_sandbox_api_token", "openai_api_key", "openai_api_key_v2", "palantir_jwt",
    "persona_production_api_key", "persona_sandbox_api_key", "pinterest_access_token", "pinterest_refresh_token", "planetscale_database_password", "planetscale_oauth_token",
    "planetscale_service_token", "plivo_auth_id", "plivo_auth_token", "postman_api_key", "postman_collection_key", "prefect_server_api_key", "prefect_user_api_key",
    "pulumi_access_token", "pypi_api_token", "readmeio_api_access_token", "redirect_pizza_api_token", "rootly_api_key", "rubygems_api_key", "samsara_api_token", "samsara_oauth_access_token",
    "segment_public_api_token", "sendgrid_api_key", "sendinblue_api_key", "sendinblue_smtp_key", "shippo_live_api_token", "shippo_test_api_token", "shopify_access_token",
    "shopify_app_client_credentials", "shopify_app_client_secret", "shopify_app_shared_secret", "shopify_custom_app_access_token", "shopify_marketplace_token", "shopify_merchant_token",
    "shopify_partner_api_token", "shopify_private_app_password", "slack_api_token", "slack_incoming_webhook_url", "slack_workflow_webhook_url", "square_access_token", "square_production_application_secret",
    "square_sandbox_application_secret", "sslmate_api_key", "sslmate_cluster_secret", "stripe_live_restricted_key", "stripe_api_key", "stripe_legacy_api_key", "stripe_test_restricted_key",
    "stripe_test_secret_key", "stripe_webhook_signing_secret", "supabase_service_key", "tableau_personal_access_token", "telegram_bot_token", "telnyx_api_v2_key", "tencent_cloud_secret_id",
    "tencent_wechat_api_app_id", "twilio_access_token", "twilio_account_sid", "twilio_api_key", "typeform_personal_access_token", "uniwise_api_key", "wakatime_pp_secret", "wakatime_oauth_access_token",
    "wakatime_oauth_refresh_token", "workato_developer_api_token", "workos_production_api_key", "workos_staging_api_key", "yandex_iam_access_secret", "yandex_cloud_api_key",
    "yandex_cloud_iam_cookie", "yandex_cloud_iam_token", "yandex_cloud_smartcaptcha_server_key", "yandex_dictionary_api_key", "yandex_passport_oauth_token", "yandex_predictor_api_key",
    "yandex_translate_api_key", "zuplo_consumer_api_key"
]

TIMESTAMP = '202402011016'
MERGED_SCAN_RESULTS_FILE = f'./reports/reports_{TIMESTAMP}/merged_scan_results_report_{TIMESTAMP}.csv'
OUTPUT_FILE='likely_ghas_matches.csv'
# The minimum match ratio to consider a match. 50% is a good starting point. 
# The ratio is calculated using the Levenshtein distance algorithm. https://en.wikipedia.org/wiki/Levenshtein_distance
FUZZ_FACTOR = 50 
# Open the input CSV file
# Open the input CSV file
match_count = 0
total_rows = 0
with open(MERGED_SCAN_RESULTS_FILE, 'r') as input_file:
    reader = csv.reader(input_file)
    # Create a CSV writer for the output file
    # Write the headers to the output file
    with open(OUTPUT_FILE, 'w', newline='') as output_file:
        writer = csv.writer(output_file)
        # Write the headers to the output file
        headers = next(reader)
        writer.writerow(headers)
    
        # Iterate over each row in the input CSV file
        for row in reader:
            total_rows += 1  # Increment the total rows counter
            # If the "match" in the row matches any GHAS pattern, write the row to the output file
            for pattern in ghas_patterns:
                if fuzz.ratio(pattern, row[6]) > FUZZ_FACTOR:  # assuming the "match" is in the seventh column
                    writer.writerow(row)
                    match_count += 1  # Increment the counter
                    print(f"Match found for pattern '{pattern}' with value '{row[6]}'")  # Print the match reason
                    break

print(f"Found {match_count} out of {total_rows} possible secrets.")
print("Output written to: likely_ghas_matches.csv")