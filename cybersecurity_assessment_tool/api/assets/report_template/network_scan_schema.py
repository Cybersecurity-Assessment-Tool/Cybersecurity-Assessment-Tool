from google.genai import types

# -----------------------------------------------------------------------------
# PORT SCAN FINDINGS SCHEMA
# -----------------------------------------------------------------------------

PORT_SCAN_FINDINGS_SCHEMA_TYPED = types.Schema(
    type=types.Type.OBJECT,
    properties={
        "findings": types.Schema(
            type=types.Type.ARRAY,
            description="A list of port scanning results and vulnerability findings for TCP and UDP ports.",
            items=types.Schema(
                type=types.Type.OBJECT,
                properties={
                    "severity": types.Schema(
                        type=types.Type.STRING, 
                        description="The severity level of the finding (e.g., 'INFO' or a specific CVE severity)."
                    ),
                    "category": types.Schema(
                        type=types.Type.STRING, 
                        description="The category of the result, typically 'port'."
                    ),
                    "description": types.Schema(
                        type=types.Type.STRING, 
                        description="A summary description of the port status (e.g., 'Open port: 80/tcp open http', 'CVE advisory', or 'Port Error')."
                    ),
                    "information": types.Schema(
                        type=types.Type.STRING, 
                        description="Detailed information or specific hardcoded findings/CVE data associated with the port."
                    ),
                    "portid": types.Schema(
                        type=types.Type.STRING, 
                        description="The port number represented as a string."
                    ),
                    "protocol": types.Schema(
                        type=types.Type.STRING, 
                        description="The transport protocol used, either 'tcp' or 'udp'."
                    ),
                    "service": types.Schema(
                        type=types.Type.STRING, 
                        description="The identified service running on the port (e.g., 'http', 'https', or 'unknown')."
                    ),
                    "scripts": types.Schema(
                        type=types.Type.ARRAY,
                        description="A list of script outputs or findings associated with the port scan.",
                        items=types.Schema(
                            type=types.Type.OBJECT,
                            description="Output from individual scanning scripts."
                        )
                    ),
                    "timestamp": types.Schema(
                        type=types.Type.STRING, 
                        description="An ISO 8601 formatted timestamp of when the port was scanned."
                    )
                },
                required=[
                    "severity", 
                    "category", 
                    "description", 
                    "information", 
                    "portid", 
                    "protocol", 
                    "service", 
                    "scripts", 
                    "timestamp"
                ]
            )
        )
    },
    required=["findings"]
)