from azure.identity import AzureCliCredential
from azure.mgmt.securityinsight import SecurityInsights
from azure.monitor.query import LogsQueryClient
from datetime import timedelta
from azure.core.exceptions import HttpResponseError

import json
import os

from llm_prompt import SYSTEM_PROMPT, call_llm

credential = AzureCliCredential()
logs_client = LogsQueryClient(credential)

subscription_id = os.environ["AZURE_SUBSCRIPTION_ID"]
resource_group = os.environ["AZURE_RESOURCE_GROUP"]
workspace_name = os.environ["AZURE_SENTINEL_WORKSPACE_NAME"]
workspace_id = os.environ["AZURE_LOG_ANALYTICS_WORKSPACE_ID"]

client = SecurityInsights(
    credential,
    subscription_id
)

telemetry_tables = [
    "Event",
    "SecurityEvent",
    "Syslog"
]
available_tables = telemetry_tables

incidents = list(client.incidents.list(
    resource_group,
    workspace_name
))

incidents.sort(
    key=lambda incident: incident.created_time_utc
)

for incident in incidents:
    if incident.status == "Closed":
        continue

    reportFolder = "incident-reports"

    os.makedirs(reportFolder, exist_ok=True)
    existingReports = os.listdir(reportFolder)
    number = len(existingReports) + 1

    fileName = f"incident-reports/incident-report-{number}-ai-assisted.md"
    report = open(fileName, "w")

    entity_response = client.incidents.list_entities(
        resource_group,
        workspace_name,
        incident.name
    )
    alert_response = client.incidents.list_alerts(
        resource_group,
        workspace_name,
        incident.name
    )

    report.write(f"# Incident Report {number}\n")
    report.write(f"## Title: {incident.title}\n\n")
    report.write(f"### Incident Overview\n")
    report.write(f"{incident.description}\n\n")
    if incident.owner.assigned_to:
        report.write(f"Case assigned to: {incident.owner.assigned_to}\n\n")
    else:
        report.write(f"Case assigned to: Unassigned\n\n")
    report.write(f"#### Attack Information:\n")
    for entity in entity_response.entities:
        report.write(f"* {entity.kind}: {entity.friendly_name}\n")

    combined_custom_details = {}
    for alert in alert_response.value:
        query = f"""
        SecurityAlert
        | where SystemAlertId == "{alert.name}"
        | project ExtendedProperties
        """

        response = logs_client.query_workspace(
            workspace_id,
            query,
            timespan=timedelta(days=30)
        )

        for table in response.tables:
            for row in table.rows:
                extended_properties = json.loads(row[0])
                custom_details = extended_properties.get("Custom Details")
                if custom_details:
                    custom_details = json.loads(custom_details)

                    for key, value in custom_details.items():
                        raw_value = value[0]

                        try:
                            parsed_value = json.loads(raw_value)
                        except (json.JSONDecodeError, TypeError):
                            parsed_value = raw_value

                        if isinstance(parsed_value, list):
                            values_to_add = parsed_value
                        else:
                            values_to_add = [parsed_value]

                        if key not in combined_custom_details:
                            combined_custom_details[key] = []

                        for item in values_to_add:
                            item = str(item).strip()

                            if item not in combined_custom_details[key]:
                                combined_custom_details[key].append(item)
    for key, values in combined_custom_details.items():
        report.write(f"* {key}: {', '.join(values)}\n")
    report.write("\n")


    entities_for_llm = []
    for entity in entity_response.entities:
        entities_for_llm.append({
            "kind": entity.kind,
            "name": entity.friendly_name
        })

    mitre_techniques = []
    for alert in alert_response.value:
        if "MitreTechniques" in alert.additional_data:
            mitre_techniques = alert.additional_data["MitreTechniques"]
            break

    incident_data = {
        "title": incident.title,
        "description": incident.description,
        "severity": incident.severity,
        "status": incident.status,
        "first_activity": str(incident.first_activity_time_utc),
        "last_activity": str(incident.last_activity_time_utc),
        "entities": entities_for_llm,
        "custom_details": combined_custom_details,
        "mitre_techniques": mitre_techniques,
    }

    llm_input = json.dumps({
        "available_tables": available_tables,
        "incident": incident_data
    }, default=str)

    previous_interaction_id = None
    report.write(f"#### AI-Assisted Analysis\n")

    while True:
        response, previous_interaction_id = call_llm(
            llm_input,
            previous_interaction_id
        )

        print("RESPONSE:", response)

        print("TYPE:", type(response))

        if response.get("kql") is not None:
            query = response["kql"]
            try:
                query_result = logs_client.query_workspace(
                    workspace_id,
                    query,
                    timespan=timedelta(days=30)
                )

            except HttpResponseError as error:
                llm_input = (
                    "The KQL query failed to execute. "
                    f"Azure returned this error: {str(error)} "
                    "Correct the KQL query and try again."
                )
                continue

            row_count = 0
            for table in query_result.tables:
                row_count += len(table.rows)

            if row_count > 500:
                llm_input = (
                    f"The KQL query returned {row_count} rows, which is too large "
                    "to return as investigation evidence. Generate a more targeted "
                    "or aggregated KQL query. You may narrow the time range, add "
                    "relevant filters, select only necessary fields, or use KQL "
                    "aggregation such as summarize where appropriate."
                )
            else:
                if "getschema" in query.lower():
                    query_result_JSON = {}

                    for table in query_result.tables:
                        column_names = []

                        for column in table.columns:
                            if hasattr(column, "name"):
                                column_names.append(column.name)
                            else:
                                column_names.append(str(column))

                        for row in table.rows:
                            schema_row = dict(zip(column_names, row))
                            query_result_JSON[schema_row.get("ColumnName")] = schema_row.get("DataType")
                else:
                    query_result_JSON = []

                    for table in query_result.tables:
                        column_names = []

                        for column in table.columns:
                            if hasattr(column, "name"):
                                column_names.append(column.name)
                            else:
                                column_names.append(str(column))

                        for row in table.rows:
                            query_result_JSON.append(dict(zip(column_names, row)))


                llm_input = json.dumps(
                    {"query_result": query_result_JSON},
                    default=str
                )


        elif response.get("final_analysis") is not None:
            analysis = response["final_analysis"]
            break

    report.write(f"{analysis}\n\n")

    report.write(f"#### Investigation Performed\n")
    report.write(f"_To be completed_\n\n")

    report.write("### Summary:\n")
    report.write(f"* Incident Title: {incident.title}\n")
    report.write(f"* Unique ID: {incident.incident_number}\n")
    report.write(f"* Severity: {incident.severity}\n")
    for alert in alert_response.value:
        if "MitreTechniques" in alert.additional_data:
            report.write(f"* Mitre Techniques: {alert.additional_data['MitreTechniques']}\n")
            break
    report.write(f"* Status: {incident.status}\n")
    report.write(f"* First activity: {incident.first_activity_time_utc}\n")
    report.write(f"* Last activity: {incident.last_activity_time_utc}\n")
    report.write(f"* Incident ID: {incident.name}\n")

    report.close()
    print(f"Incident report generated: {fileName}")

print("All incident reports for open incidents have been generated.")