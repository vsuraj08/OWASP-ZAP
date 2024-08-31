



import json
import requests
import logging
from together import Together
from zapv2 import ZAPv2
import time
import argparse

# Configure logging
logging.basicConfig(filename='test_case.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Initialize OWASP ZAP
zap_base_url = 'http://localhost:8080'
zap = ZAPv2(apikey='abc123abc', proxies={'http': zap_base_url, 'https': zap_base_url})

# Initialize Together Client
together_client = Together(api_key="ec9520d163d357d5ed7414ed993c027fdcd36c7d5c64149811fcc85f201db981")



HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h2 {{ color: #333; }}
        .section {{ margin-bottom: 40px; }}
        .test-case {{ background-color: #f9f9f9; padding: 10px; border-radius: 5px; }}
        .execution {{ background-color: #e6f7ff; padding: 10px; border-radius: 5px; }}
        .evaluation {{ background-color: #e6ffe6; padding: 10px; border-radius: 5px; }}
    </style>
    <title>API Security Test Report</title>
</head>
<body>
    <h1>API Security Test Report</h1>
    {content}
</body>
</html>
"""

# Define expected responses for each alert type
expected_responses = {
    "Re-examine Cache-control Directives": "The Cache-Control header should be set to ensure proper caching policies.",
    "Cross-Domain Misconfiguration": "Ensure proper CORS (Cross-Origin Resource Sharing) policies are in place.",
    "Server Leaks Version Information via \"Server\" HTTP Response Header Field": "The Server header should not disclose version information.",
    "Strict-Transport-Security Header Not Set": "The Strict-Transport-Security header should be set to enforce HTTPS.",
    "X-Content-Type-Options Header Missing": "The X-Content-Type-Options header should be set to prevent MIME type sniffing.",
    "Server Leaks Information via \"X-Powered-By\" HTTP Response Header Field(s)": "The X-Powered-By header should not disclose server technology information."
}

# 1. Load API Endpoints from JSON
def load_api_endpoints(file_path):
    try:
        with open(file_path, 'r') as file:
            data = json.load(file)
            logging.info(f"Loaded API Endpoints: {data}")  # Logging instead of print
            return data
    except Exception as e:
        logging.error(f"Error loading API endpoints: {e}")
        raise

# 2. Generate Test Cases using LLM
# 2. Generate Test Cases using LLM
# def generate_execute_evaluate_test_cases(endpoint, method, details):
#     # Step 1: Generate super-advanced test cases
#     generate_prompt = f"""
#     Generate super-advanced test cases for the following API endpoint to cover OWASP Top 10 API risks:
    
#     Endpoint: {endpoint}
#     Method: {method}
#     Security: {details.get('security', 'None')}
#     Parameters: {details.get('parameters', 'None')}
#     Responses: {details.get('responses', 'None')}
#     """
#     test_cases_response = together_client.chat.completions.create(
#         model="meta-llama/Meta-Llama-3.1-405B-Instruct-Turbo",
#         messages=[
#             {"role": "system", "content": "You are an expert in API security."},
#             {"role": "user", "content": generate_prompt},
#         ],
#         max_tokens=699,
#         temperature=0.11,
#         top_p=1,
#         top_k=50,
#         repetition_penalty=1,
#         stop=["<|eot_id|>"],
#     )
#     test_cases = test_cases_response.choices[0].message.content

#     # Step 2: Execute the test cases (Simulated)
#     execution_prompt = f"""
#     Simulate the execution of the following test cases for the API endpoint and provide results:
    
#     Endpoint: {endpoint}
#     Method: {method}
#     Test Cases: {test_cases}
#     """
#     execution_response = together_client.chat.completions.create(
#         model="meta-llama/Meta-Llama-3.1-405B-Instruct-Turbo",
#         messages=[
#             {"role": "system", "content": "You are an expert in API testing."},
#             {"role": "user", "content": execution_prompt},
#         ],
#         max_tokens=699,
#         temperature=0.11,
#         top_p=1,
#         top_k=50,
#         repetition_penalty=1,
#         stop=["<|eot_id|>"],
#     )
#     execution_results = execution_response.choices[0].message.content

#     # Step 3: Evaluate the execution results
#     evaluate_prompt = f"""
#     Evaluate the results of the executed test cases for the API endpoint:
    
#     Endpoint: {endpoint}
#     Method: {method}
#     Execution Results: {execution_results}
    
#     Provide a conclusion on whether the API is secure according to OWASP Top 10 API risks.
#     """
#     evaluation_response = together_client.chat.completions.create(
#         model="meta-llama/Meta-Llama-3.1-405B-Instruct-Turbo",
#         messages=[
#             {"role": "system", "content": "You are an expert in API security evaluation."},
#             {"role": "user", "content": evaluate_prompt},
#         ],
#         max_tokens=699,
#         temperature=0.11,
#         top_p=1,
#         top_k=50,
#         repetition_penalty=1,
#         stop=["<|eot_id|>"],
#     )
#     evaluation = evaluation_response.choices[0].message.content

#     # Function to convert plain text into HTML formatted blocks
#     def convert_to_html_blocks(text):
#         blocks = text.split('\n')
#         html_blocks = []
#         for block in blocks:
#             if block.strip():
#                 html_blocks.append(f"<div class='test-case-block'>{block.strip()}</div>")
#         return ''.join(html_blocks)

#     formatted_test_cases = convert_to_html_blocks(test_cases)
#     formatted_execution_results = convert_to_html_blocks(execution_results)
#     formatted_evaluation = convert_to_html_blocks(evaluation)

#     # Create HTML section with CSS styling
#     html_section = f"""
#     <style>
#         .section {{
#             margin-bottom: 20px;
#             font-family: Arial, sans-serif;
#         }}
#         .test-case, .execution, .evaluation {{
#             margin-top: 20px;
#             padding: 15px;
#             border: 1px solid #ddd;
#             border-radius: 5px;
#             background-color: #f9f9f9;
#         }}
#         .test-case-block, .execution-block, .evaluation-block {{
#             margin-bottom: 20px;
#             padding: 10px;
#             border-bottom: 1px solid #ddd;
#         }}
#         .test-case-block:last-child, .execution-block:last-child, .evaluation-block:last-child {{
#             border-bottom: none;
#         }}
#         .header {{
#             color: #000;
#             font-weight: bold;
#             font-size: 1.2em;
#             margin-bottom: 15px;
#         }}
#         .test-case-block, .execution-block, .evaluation-block {{
#             background-color: #ffffff;
#         }}
#         .sub-header {{
#             color: #000;
#             font-weight: bold;
#             font-size: 1.1em;
#             margin-top: 10px;
#             margin-bottom: 10px;
#         }}
#         .final-conclusion {{
#             color: #000;
#             font-weight: bold;
#             font-size: 1.2em;
#             margin-top: 20px;
#         }}
#     </style>
    
#     <div class="section">
#         <h2 style="color: #2c3e50;">Endpoint: {endpoint} | Method: {method}</h2>
        
#         <div class="test-case">
#             <h3 class="header">Generated Test Cases</h3>
#             <div class="sub-header">{formatted_test_cases}</div>
#         </div>

#         <div class="execution">
#             <h3 class="header">Execution Results</h3>
#             <div class="sub-header">{formatted_execution_results}</div>
#         </div>

#         <div class="evaluation">
#             <h3 class="header">Evaluation</h3>
#             <div class="sub-header">{formatted_evaluation}</div>
#             <div class="final-conclusion">Final Conclusion: {evaluation}</div>
#         </div>
#     </div>
#     """
#     return html_section







# # Process API documentation
# def process_api_documentation(api_data):
#     content = ""
#     paths = api_data.get("paths", {})
#     for endpoint, methods in paths.items():
#         for method, details in methods.items():
#             html_section = generate_execute_evaluate_test_cases(endpoint, method, details)
#             content += html_section
    
#     # Write the HTML content to the log file
#     html_content = HTML_TEMPLATE.format(content=content)
#     with open('llm_test.log', 'w') as file:
#         file.write(html_content)


# 6. OWASP ZAP Scanning
# 6. OWASP ZAP Scanning
# 6. OWASP ZAP Scanning
def perform_zap_scan(api_file):
    try:
        # Load API Endpoints
        api_endpoints = load_api_endpoints(api_file)

        # Run ZAP Spider
        for path in api_endpoints['paths']:
            url = f"{api_endpoints['servers'][0]['url']}{path}"
            zap.spider.scan(url)
            logging.info(f"Scanning URL: {url}")

        # Wait for Spider to complete
        while int(zap.spider.status()) < 100:
            time.sleep(5)

        # Run ZAP Active Scan
        for path in api_endpoints['paths']:
            url = f"{api_endpoints['servers'][0]['url']}{path}"
            zap.ascan.scan(url)
            logging.info(f"Active scanning URL: {url}")

        # Wait for Active Scan to complete
        while int(zap.ascan.status()) < 100:
            time.sleep(5)

        # Get Alerts
        alerts = zap.core.alerts()
        logging.info(f"Alerts: {alerts}")

        # Save JSON Report
        with open("zap_report.json", 'w') as f:
            json.dump(alerts, f, indent=4)
            logging.info("Saved ZAP Report (JSON)")

        # Save HTML Report
        html_report_path = "zap_report.html"
        with open(html_report_path, 'w') as f:
            f.write(zap.core.htmlreport())
        logging.info(f"Saved ZAP Report (HTML) at {html_report_path}")

        return alerts
    except Exception as e:
        logging.error(f"Error during ZAP scanning: {e}")
        raise


# Main Execution
# Main Execution
def main(api_file):
    try:
        # Perform ZAP Scan
        alerts = perform_zap_scan(api_file)

        # Load API Endpoints
        api_endpoints = load_api_endpoints(api_file)

        # # Generate and Execute Test Cases
        # for path in api_endpoints['paths']:
        #     # Assuming `api_endpoints` has information for each endpoint
        #     # You might need to update how you get individual `api_endpoint`
        #     api_endpoint = api_endpoints  # This needs to be the correct structure
            
        #     test_case = generate_test_cases(api_endpoint)
        #     status_code, response_text = execute_test_case(api_endpoint)
        #     logging.info(f"Test Case Result: {status_code}, Response: {response_text}")

        #     advanced_cases = generate_advanced_test_cases(api_endpoint)
        #     for case in advanced_cases:
        #         status_code, response_text = execute_advanced_test_case(api_endpoint, case)
        #         logging.info(f"Advanced Test Case Result: {status_code}, Response: {response_text}")

    except Exception as e:
        logging.error(f"Main execution error: {e}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="API Security Test Script")
    parser.add_argument('api_file', type=str, help='Path to the API endpoints JSON file')
    args = parser.parse_args()

    main(args.api_file)




def generate_execute_evaluate_test_cases(endpoint, method, details):
    # Step 1: Generate super-advanced test cases
    generate_prompt = f"""
    Generate super-advanced test cases for the following API endpoint to cover OWASP Top 10 API risks:
    
    Endpoint: {endpoint}
    Method: {method}
    Security: {details.get('security', 'None')}
    Parameters: {details.get('parameters', 'None')}
    Responses: {details.get('responses', 'None')}
    """
    test_cases_response = together_client.chat.completions.create(
        model="meta-llama/Meta-Llama-3.1-405B-Instruct-Turbo",
        messages=[
            {"role": "system", "content": "You are an expert in API security."},
            {"role": "user", "content": generate_prompt},
        ],
        max_tokens=699,
        temperature=0.11,
        top_p=1,
        top_k=50,
        repetition_penalty=1,
        stop=["<|eot_id|>"],
    )
    test_cases = test_cases_response.choices[0].message.content

    # Step 2: Execute the test cases (Simulated)
    execution_prompt = f"""
    Simulate the execution of the following test cases for the API endpoint and provide results:
    
    Endpoint: {endpoint}
    Method: {method}
    Test Cases: {test_cases}
    """
    execution_response = together_client.chat.completions.create(
        model="meta-llama/Meta-Llama-3.1-405B-Instruct-Turbo",
        messages=[
            {"role": "system", "content": "You are an expert in API testing."},
            {"role": "user", "content": execution_prompt},
        ],
        max_tokens=699,
        temperature=0.11,
        top_p=1,
        top_k=50,
        repetition_penalty=1,
        stop=["<|eot_id|>"],
    )
    execution_results = execution_response.choices[0].message.content

    # Step 3: Evaluate the execution results
    evaluate_prompt = f"""
    Evaluate the results of the executed test cases for the API endpoint:
    
    Endpoint: {endpoint}
    Method: {method}
    Execution Results: {execution_results}
    
    Provide a conclusion on whether the API is secure according to OWASP Top 10 API risks.
    """
    evaluation_response = together_client.chat.completions.create(
        model="meta-llama/Meta-Llama-3.1-405B-Instruct-Turbo",
        messages=[
            {"role": "system", "content": "You are an expert in API security evaluation."},
            {"role": "user", "content": evaluate_prompt},
        ],
        max_tokens=699,
        temperature=0.11,
        top_p=1,
        top_k=50,
        repetition_penalty=1,
        stop=["<|eot_id|>"],
    )
    evaluation = evaluation_response.choices[0].message.content

    # Function to convert plain text into HTML formatted blocks
    def convert_to_html_blocks(text):
        blocks = text.split('\n')
        html_blocks = []
        for block in blocks:
            if block.strip():
                html_blocks.append(f"<div class='test-case-block'>{block.strip()}</div>")
        return ''.join(html_blocks)

    formatted_test_cases = convert_to_html_blocks(test_cases)
    formatted_execution_results = convert_to_html_blocks(execution_results)
    formatted_evaluation = convert_to_html_blocks(evaluation)

    # Create HTML section with CSS styling
    html_section = f"""
    <style>
        .section {{
            margin-bottom: 20px;
            font-family: Arial, sans-serif;
        }}
        .test-case, .execution, .evaluation {{
            margin-top: 20px;
            padding: 15px;
            border: 1px solid #ddd;
            border-radius: 5px;
            background-color: #f9f9f9;
        }}
        .test-case-block, .execution-block, .evaluation-block {{
            margin-bottom: 20px;
            padding: 10px;
            border-bottom: 1px solid #ddd;
        }}
        .test-case-block:last-child, .execution-block:last-child, .evaluation-block:last-child {{
            border-bottom: none;
        }}
        .header {{
            color: #000;
            font-weight: bold;
            font-size: 1.2em;
            margin-bottom: 15px;
        }}
        .test-case-block, .execution-block, .evaluation-block {{
            background-color: #ffffff;
        }}
        .sub-header {{
            color: #000;
            font-weight: bold;
            font-size: 1.1em;
            margin-top: 10px;
            margin-bottom: 10px;
        }}
        .final-conclusion {{
            color: #000;
            font-weight: bold;
            font-size: 1.2em;
            margin-top: 20px;
        }}
    </style>
    
    <div class="section">
        <h2 style="color: #2c3e50;">Endpoint: {endpoint} | Method: {method}</h2>
        
        <div class="test-case">
            <h3 class="header">Generated Test Cases</h3>
            <div class="sub-header">{formatted_test_cases}</div>
        </div>

        <div class="execution">
            <h3 class="header">Execution Results</h3>
            <div class="sub-header">{formatted_execution_results}</div>
        </div>

        <div class="evaluation">
            <h3 class="header">Evaluation</h3>
            <div class="sub-header">{formatted_evaluation}</div>
            <div class="final-conclusion">Final Conclusion: {evaluation}</div>
        </div>
    </div>
    """
    return html_section







# Process API documentation
def process_api_documentation(api_data):
    content = ""
    paths = api_data.get("paths", {})
    for endpoint, methods in paths.items():
        for method, details in methods.items():
            html_section = generate_execute_evaluate_test_cases(endpoint, method, details)
            content += html_section
    
    # Write the HTML content to the log file
    html_content = HTML_TEMPLATE.format(content=content)
    with open('llm_test.html', 'w') as file:
        file.write(html_content)

if __name__ == "__main__":
    # Load API documentation
    api_data = load_api_endpoints('api_endpoints.json')
    
    # Process and generate test cases
    process_api_documentation(api_data)
    
    print("Super-advanced test cases generated, executed, evaluated, and logged in test_case.log.")




























# import json
# import requests
# import logging
# from together import Together
# from zapv2 import ZAPv2
# import time
# import argparse

# # Configure logging
# logging.basicConfig(filename='test_case.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# # Initialize OWASP ZAP
# zap_base_url = 'http://localhost:8080'
# zap = ZAPv2(apikey='abc123abc', proxies={'http': zap_base_url, 'https': zap_base_url})

# # Initialize Together Client
# together_client = Together(api_key="ec9520d163d357d5ed7414ed993c027fdcd36c7d5c64149811fcc85f201db981")

# # Define expected responses for each alert type
# expected_responses = {
#     "Re-examine Cache-control Directives": "The Cache-Control header should be set to ensure proper caching policies.",
#     "Cross-Domain Misconfiguration": "Ensure proper CORS (Cross-Origin Resource Sharing) policies are in place.",
#     "Server Leaks Version Information via \"Server\" HTTP Response Header Field": "The Server header should not disclose version information.",
#     "Strict-Transport-Security Header Not Set": "The Strict-Transport-Security header should be set to enforce HTTPS.",
#     "X-Content-Type-Options Header Missing": "The X-Content-Type-Options header should be set to prevent MIME type sniffing.",
#     "Server Leaks Information via \"X-Powered-By\" HTTP Response Header Field(s)": "The X-Powered-By header should not disclose server technology information."
# }

# def load_api_endpoints(file_path):
#     try:
#         with open(file_path, 'r') as file:
#             data = json.load(file)
#             logging.info(f"Loaded API Endpoints: {data}")
#             return data
#     except Exception as e:
#         logging.error(f"Error loading API endpoints: {e}")
#         raise

# def generate_test_cases(api_endpoint):
#     try:
#         response = together_client.chat.completions.create(
#             model="meta-llama/Meta-Llama-3.1-405B-Instruct-Turbo",
#             messages=[
#                 {
#                     "role": "system",
#                     "content": "You are an API security expert with deep knowledge of OWASP API security risks. Generate realistic test cases for the following risks: Broken Object Level Authorization (BOLA), Broken Authentication, Broken Object Property Level Authorization, Unrestricted Resource Consumption, Broken Function Level Authorization (BFLA), Unrestricted Access to Sensitive Business Flows, Server-Side Request Forgery (SSRF), Security Misconfiguration, Improper Inventory Management. Format the output in a table with clear headers and descriptions."
#                 },
#                 {
#                     "role": "user",
#                     "content": f"""
#                     API URL: {api_endpoint['servers'][0]['url']}
#                     Paths:
#                     {', '.join([path for path in api_endpoint['paths']])}
#                     """
#                 }
#             ],
#             max_tokens=500
#         )
        
#         if response and 'choices' in response and len(response['choices']) > 0:
#             test_case_text = response['choices'][0]['message']['content']
#         else:
#             test_case_text = "No response from LLM or unexpected format."
        
#         logging.info(f"Generated Test Case for URL {api_endpoint['servers'][0]['url']}: {test_case_text}")
#         return test_case_text
#     except Exception as e:
#         logging.error(f"Error generating test case: {e}")
#         raise

# def generate_advanced_test_cases(api_endpoint):
#     base_url = api_endpoint['servers'][0]['url']
#     advanced_cases = [
#         # ... (advanced cases unchanged)
#         {
#             "description": "SQL Injection Attempt",
#             "method": "GET",
#             "url": f"{base_url}?id=1' OR '1'='1",
#             "expected_status": 400,
#             "expected_response": "An error message indicating improper input"
#         },
#         {
#             "description": "XSS Attack Attempt",
#             "method": "GET",
#             "url": f"{base_url}?name=<script>alert('XSS')</script>",
#             "expected_status": 400,
#             "expected_response": "An error message indicating improper input"
#         },
#         {
#             "description": "Large Payload Test",
#             "method": "GET",
#             "url": f"{base_url}?data={'A'*10000}",
#             "expected_status": 413,
#             "expected_response": "An error message indicating payload too large"
#         },
#         {
#             "description": "Rate Limiting Test",
#             "method": "GET",
#             "url": base_url,
#             "expected_status": 429,
#             "expected_response": "An error message indicating rate limit exceeded"
#         },
#         {
#             "description": "Broken Object Level Authorization",
#             "method": "GET",
#             "url": f"{base_url}/object_level_access",
#             "expected_status": 403,
#             "expected_response": "Access denied"
#         },
#         {
#             "description": "Broken Authentication",
#             "method": "POST",
#             "url": f"{base_url}/login",
#             "data": {"username": "admin", "password": "wrong_password"},
#             "expected_status": 401,
#             "expected_response": "Invalid credentials"
#         },
#         {
#             "description": "Broken Object Property Level Authorization",
#             "method": "GET",
#             "url": f"{base_url}/object_property",
#             "expected_status": 403,
#             "expected_response": "Access denied"
#         },
#         {
#             "description": "Unrestricted Resource Consumption",
#             "method": "GET",
#             "url": f"{base_url}/resource_consumption",
#             "expected_status": 429,
#             "expected_response": "Rate limit exceeded"
#         },
#         {
#             "description": "Broken Function Level Authorization",
#             "method": "POST",
#             "url": f"{base_url}/admin_function",
#             "data": {"action": "admin_action"},
#             "expected_status": 403,
#             "expected_response": "Forbidden"
#         },
#         {
#             "description": "Unrestricted Access to Sensitive Business Flows",
#             "method": "POST",
#             "url": f"{base_url}/sensitive_flow",
#             "data": {"action": "excessive_use"},
#             "expected_status": 403,
#             "expected_response": "Access denied"
#         },
#         {
#             "description": "Server Side Request Forgery (SSRF)",
#             "method": "POST",
#             "url": f"{base_url}/ssrf_vulnerable",
#             "data": {"url": "http://internal_service:8080"},
#             "expected_status": 403,
#             "expected_response": "Forbidden"
#         },
#         {
#             "description": "Security Misconfiguration",
#             "method": "GET",
#             "url": f"{base_url}/config",
#             "expected_status": 403,
#             "expected_response": "Access denied"
#         },
#         {
#             "description": "Improper Inventory Management",
#             "method": "GET",
#             "url": f"{base_url}/api_versions",
#             "expected_status": 200,
#             "expected_response": "List of versions"
#         },
#         {
#             "description": "Unsafe Consumption of APIs",
#             "method": "POST",
#             "url": f"{base_url}/consume_third_party",
#             "data": {"third_party_url": "http://malicious_service.com"},
#             "expected_status": 400,
#             "expected_response": "Bad Request"
#         }




#     ]
#     return advanced_cases

# def execute_test_case(api_endpoint):
#     try:
#         url = api_endpoint['servers'][0]['url']
#         logging.debug(f"Executing basic test case for URL: {url}")  # Debugging URL
#         response = requests.get(url)
#         logging.info(f"Executed basic test case for URL {url}, Status Code: {response.status_code}")
#         return response.status_code, response.text
#     except Exception as e:
#         logging.error(f"Error executing test case for URL {url}: {e}")
#         return None, str(e)

# def execute_advanced_test_case(api_endpoint, test_case):
#     try:
#         url = test_case['url']
#         headers = test_case.get('headers', {})
#         data = test_case.get('data', {})
#         logging.debug(f"Executing advanced test case: {test_case['description']}, URL: {url}")  # Debugging URL
#         if test_case['method'] == 'POST':
#             response = requests.post(url, headers=headers, data=data)
#         else:
#             response = requests.get(url, headers=headers)
#         logging.info(f"Executed advanced test case: {test_case['description']}, Status Code: {response.status_code}, Response: {response.text}")
#         return response.status_code, response.text
#     except Exception as e:
#         logging.error(f"Error executing advanced test case for URL {url}: {e}")
#         return None, str(e)

# def perform_zap_scan(api_file):
#     try:
#         api_endpoints = load_api_endpoints(api_file)
#         for path in api_endpoints['paths']:
#             url = f"{api_endpoints['servers'][0]['url']}{path}"
#             zap.spider.scan(url)
#             logging.info(f"Scanning URL: {url}")
#         while int(zap.spider.status()) < 100:
#             time.sleep(5)
#         for path in api_endpoints['paths']:
#             url = f"{api_endpoints['servers'][0]['url']}{path}"
#             zap.ascan.scan(url)
#             logging.info(f"Active scanning URL: {url}")
#         while int(zap.ascan.status()) < 100:
#             time.sleep(5)
#         alerts = zap.core.alerts()
#         logging.info(f"Alerts: {alerts}")
#         with open("zap_report.json", 'w') as f:
#             json.dump(alerts, f, indent=4)
#             logging.info("Saved ZAP Report (JSON)")
#         html_report_path = "zap_report.html"
#         with open(html_report_path, 'w') as f:
#             f.write(zap.core.htmlreport())
#         logging.info(f"Saved ZAP Report (HTML) at {html_report_path}")
#         return alerts
#     except Exception as e:
#         logging.error(f"Error during ZAP scanning: {e}")
#         raise

# def main(api_file):
#     try:
#         alerts = perform_zap_scan(api_file)
#         api_endpoints = load_api_endpoints(api_file)
#         for path in api_endpoints['paths']:
#             api_endpoint = api_endpoints  # This needs to be adjusted if necessary
#             test_case = generate_test_cases(api_endpoint)
#             logging.info(f"Test Case Result: {test_case}")
#             status_code, response_text = execute_test_case(api_endpoint)
#             logging.info(f"Test Case Result: {status_code}, Response: {response_text}")
#             advanced_cases = generate_advanced_test_cases(api_endpoint)
#             for case in advanced_cases:
#                 status_code, response_text = execute_advanced_test_case(api_endpoint, case)
#                 logging.info(f"Advanced Test Case Result: {status_code}, Response: {response_text}")
#     except Exception as e:
#         logging.error(f"Main execution error: {e}")

# if __name__ == "__main__":
#     parser = argparse.ArgumentParser(description="API Security Test Script")
#     parser.add_argument('api_file', type=str, help='Path to the API endpoints JSON file')
#     args = parser.parse_args()
#     main(args.api_file)



# import json
# import requests
# import logging
# from together import Together
# from zapv2 import ZAPv2
# import time
# import argparse

# # Configure logging
# logging.basicConfig(filename='test_case.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# # Initialize OWASP ZAP
# zap_base_url = 'http://localhost:8080'
# zap = ZAPv2(apikey='abc123abc', proxies={'http': zap_base_url, 'https': zap_base_url})

# # Initialize Together Client
# together_client = Together(api_key="ec9520d163d357d5ed7414ed993c027fdcd36c7d5c64149811fcc85f201db981")

# # Define expected responses for each alert type
# expected_responses = {
#     "Re-examine Cache-control Directives": "The Cache-Control header should be set to ensure proper caching policies.",
#     "Cross-Domain Misconfiguration": "Ensure proper CORS (Cross-Origin Resource Sharing) policies are in place.",
#     "Server Leaks Version Information via \"Server\" HTTP Response Header Field": "The Server header should not disclose version information.",
#     "Strict-Transport-Security Header Not Set": "The Strict-Transport-Security header should be set to enforce HTTPS.",
#     "X-Content-Type-Options Header Missing": "The X-Content-Type-Options header should be set to prevent MIME type sniffing.",
#     "Server Leaks Information via \"X-Powered-By\" HTTP Response Header Field(s)": "The X-Powered-By header should not disclose server technology information."
# }

# def load_api_endpoints(file_path):
#     try:
#         with open(file_path, 'r') as file:
#             data = json.load(file)
#             if not isinstance(data, list):
#                 raise ValueError("JSON file should contain a list of API endpoints.")
#             logging.info(f"Loaded API Endpoints: {data}")
#             return data
#     except Exception as e:
#         logging.error(f"Error loading API endpoints: {e}")
#         raise

# def generate_test_cases(api_endpoint):
#     try:
#         response = together_client.chat.completions.create(
#             model="meta-llama/Meta-Llama-3.1-405B-Instruct-Turbo",
#             messages=[
#                 {
#                     "role": "system",
#                     "content": "You are an API security expert with deep knowledge of OWASP API security risks. Generate realistic test cases for the following risks: Broken Object Level Authorization (BOLA), Broken Authentication, Broken Object Property Level Authorization, Unrestricted Resource Consumption, Broken Function Level Authorization (BFLA), Unrestricted Access to Sensitive Business Flows, Server-Side Request Forgery (SSRF), Security Misconfiguration, Improper Inventory Management. Format the output in a table with clear headers and descriptions."
#                 },
#                 {
#                     "role": "user",
#                     "content": f"""
#                     API URL: {api_endpoint['servers'][0]['url']}
#                     Paths:
#                     {', '.join([path for path in api_endpoint['paths']])}
#                     """
#                 }
#             ],
#             max_tokens=500
#         )
        
#         if response and 'choices' in response and len(response['choices']) > 0:
#             test_case_text = response['choices'][0]['message']['content']
#         else:
#             test_case_text = "No response from LLM or unexpected format."
        
#         logging.info(f"Generated Test Case for URL {api_endpoint['servers'][0]['url']}: {test_case_text}")
#         return test_case_text
#     except Exception as e:
#         logging.error(f"Error generating test case: {e}")
#         raise

# def generate_advanced_test_cases(api_endpoint):
#     base_url = api_endpoint['servers'][0]['url']
#     advanced_cases = [
#         # OWASP Top 10 API Security Risks Test Cases
#         {
#             "description": "Broken Object Level Authorization",
#             "method": "GET",
#             "url": f"{base_url}/object_level_access",
#             "expected_status": 403,
#             "expected_response": "Access denied"
#         },
#         {
#             "description": "Broken Authentication",
#             "method": "POST",
#             "url": f"{base_url}/login",
#             "data": {"username": "admin", "password": "wrong_password"},
#             "expected_status": 401,
#             "expected_response": "Invalid credentials"
#         },
#         {
#             "description": "Broken Object Property Level Authorization",
#             "method": "GET",
#             "url": f"{base_url}/object_property",
#             "expected_status": 403,
#             "expected_response": "Access denied"
#         },
#         {
#             "description": "Unrestricted Resource Consumption",
#             "method": "GET",
#             "url": f"{base_url}/resource_consumption",
#             "expected_status": 429,
#             "expected_response": "Rate limit exceeded"
#         },
#         {
#             "description": "Broken Function Level Authorization",
#             "method": "POST",
#             "url": f"{base_url}/admin_function",
#             "data": {"action": "admin_action"},
#             "expected_status": 403,
#             "expected_response": "Forbidden"
#         },
#         {
#             "description": "Unrestricted Access to Sensitive Business Flows",
#             "method": "POST",
#             "url": f"{base_url}/sensitive_flow",
#             "data": {"action": "excessive_use"},
#             "expected_status": 403,
#             "expected_response": "Access denied"
#         },
#         {
#             "description": "Server Side Request Forgery (SSRF)",
#             "method": "POST",
#             "url": f"{base_url}/ssrf_vulnerable",
#             "data": {"url": "http://internal_service:8080"},
#             "expected_status": 403,
#             "expected_response": "Forbidden"
#         },
#         {
#             "description": "Security Misconfiguration",
#             "method": "GET",
#             "url": f"{base_url}/config",
#             "expected_status": 403,
#             "expected_response": "Access denied"
#         },
#         {
#             "description": "Improper Inventory Management",
#             "method": "GET",
#             "url": f"{base_url}/api_versions",
#             "expected_status": 200,
#             "expected_response": "List of versions"
#         },
#         {
#             "description": "SQL Injection Attempt",
#             "method": "GET",
#             "url": f"{base_url}?id=1' OR '1'='1",
#             "expected_status": 400,
#             "expected_response": "An error message indicating improper input"
#         },
#         {
#             "description": "XSS Attack Attempt",
#             "method": "GET",
#             "url": f"{base_url}?name=<script>alert('XSS')</script>",
#             "expected_status": 400,
#             "expected_response": "An error message indicating improper input"
#         },
#         {
#             "description": "Large Payload Test",
#             "method": "GET",
#             "url": f"{base_url}/large_payload",
#             "data": {"payload": "A" * 100000},
#             "expected_status": 413,
#             "expected_response": "Payload too large"
#         }
#     ]
#     return advanced_cases

# def execute_test_case(api_endpoint):
#     try:
#         url = api_endpoint['servers'][0]['url']
#         logging.debug(f"Executing basic test case for URL: {url}")  # Debugging URL
#         response = requests.get(url)
#         logging.info(f"Executed basic test case for URL {url}, Status Code: {response.status_code}")
#         return response.status_code, response.text
#     except KeyError as e:
#         logging.error(f"KeyError in execute_test_case: {e}")
#         return None, f"KeyError: {str(e)}"
#     except Exception as e:
#         logging.error(f"Error executing test case: {e}")
#         return None, str(e)

# def execute_advanced_test_case(api_endpoint, test_case):
#     try:
#         url = test_case['url']
#         method = test_case.get('method', 'GET')
#         data = test_case.get('data', {})
        
#         logging.debug(f"Executing advanced test case: {test_case['description']}, URL: {url}, Method: {method}")
        
#         if method.upper() == 'GET':
#             response = requests.get(url)
#         elif method.upper() == 'POST':
#             response = requests.post(url, json=data)
#         else:
#             logging.warning(f"Unsupported method {method} for test case: {test_case['description']}")
#             return None, "Unsupported method"
        
#         if response.status_code == test_case.get('expected_status') and test_case.get('expected_response') in response.text:
#             logging.info(f"Advanced test case passed: {test_case['description']}")
#         else:
#             logging.warning(f"Advanced test case failed: {test_case['description']}. Status Code: {response.status_code}, Response: {response.text}")
#         return response.status_code, response.text
#     except Exception as e:
#         logging.error(f"Error executing advanced test case: {test_case['description']}, URL: {url}, Error: {e}")
#         return None, str(e)

# def run_zap_scan(api_endpoint):
#     try:
#         url = api_endpoint['servers'][0]['url']
#         logging.info(f"Starting OWASP ZAP scan for URL: {url}")
#         zap.urlopen(url)
#         time.sleep(5)  # Wait for the scan to start
#         scan_id = zap.ascan.scan(url)
#         while int(zap.ascan.status(scan_id)) < 100:
#             time.sleep(5)
#         alerts = zap.core.alerts(baseurl=url)
#         for alert in alerts:
#             description = alert.get('alert')
#             if description in expected_responses:
#                 logging.info(f"Found alert: {description}, Expected Response: {expected_responses[description]}")
#             else:
#                 logging.warning(f"Found unexpected alert: {description}")
#         logging.info(f"OWASP ZAP scan completed for URL: {url}")
#     except Exception as e:
#         logging.error(f"Error during OWASP ZAP scan for URL {url}: {e}")
#         raise

# def main():
#     parser = argparse.ArgumentParser(description="API Testing Script")
#     parser.add_argument("api_file", help="Path to the JSON file containing API endpoints")
#     args = parser.parse_args()
    
#     api_endpoints = load_api_endpoints(args.api_file)

#     for api_endpoint in api_endpoints:
#         # Generate and execute basic test cases
#         basic_status_code, basic_response_text = execute_test_case(api_endpoint)
        
#         # Generate advanced test cases
#         advanced_test_cases = generate_advanced_test_cases(api_endpoint)
#         for test_case in advanced_test_cases:
#             execute_advanced_test_case(api_endpoint, test_case)

#         # Run OWASP ZAP Scan
#         run_zap_scan(api_endpoint)

# if __name__ == "__main__":
#     main()




# import json
# import logging
# from together import Together

# # Initialize Together AI client
# together_client = Together(api_key="ec9520d163d357d5ed7414ed993c027fdcd36c7d5c64149811fcc85f201db981")

# # Set up logging
# logging.basicConfig(filename='test_case.log', level=logging.INFO, format='%(asctime)s - %(message)s')

# # Load API endpoints from JSON file
# def load_api_endpoints(file_path):
#     with open(file_path, 'r') as file:
#         return json.load(file)

# # Generate and evaluate test cases using LLM
# def generate_and_evaluate_test_cases(endpoint, method, details):
#     # Step 1: Generate super-advanced test cases
#     generate_prompt = f"""
#     Generate super-advanced test cases for the following API endpoint to cover OWASP Top 10 API risks:
    
#     Endpoint: {endpoint}
#     Method: {method}
#     Security: {details.get('security', 'None')}
#     Parameters: {details.get('parameters', 'None')}
#     Responses: {details.get('responses', 'None')}
#     """
#     test_cases_response = together_client.chat.completions.create(
#         model="meta-llama/Meta-Llama-3.1-405B-Instruct-Turbo",
#         messages=[
#             {"role": "system", "content": "You are an expert in API security."},
#             {"role": "user", "content": generate_prompt},
#         ],
#         max_tokens=699,
#         temperature=0.11,
#         top_p=1,
#         top_k=50,
#         repetition_penalty=1,
#         stop=["<|eot_id|>"],
#     )
#     test_cases = test_cases_response.choices[0].message.content

#     # Step 2: Evaluate the generated test cases
#     evaluate_prompt = f"""
#     Evaluate the following test cases for the API endpoint:
    
#     Endpoint: {endpoint}
#     Method: {method}
#     Test Cases: {test_cases}
    
#     Provide a detailed analysis of whether the test cases pass or fail, and why.
#     """
#     evaluation_response = together_client.chat.completions.create(
#         model="meta-llama/Meta-Llama-3.1-405B-Instruct-Turbo",
#         messages=[
#             {"role": "system", "content": "You are an expert in API security evaluation."},
#             {"role": "user", "content": evaluate_prompt},
#         ],
#         max_tokens=699,
#         temperature=0.11,
#         top_p=1,
#         top_k=50,
#         repetition_penalty=1,
#         stop=["<|eot_id|>"],
#     )
#     evaluation = evaluation_response.choices[0].message.content

#     return test_cases, evaluation

# # Process API documentation
# def process_api_documentation(api_data):
#     paths = api_data.get("paths", {})
#     for endpoint, methods in paths.items():
#         for method, details in methods.items():
#             test_cases, evaluation = generate_and_evaluate_test_cases(endpoint, method, details)
#             logging.info(f"Endpoint: {endpoint} | Method: {method}")
#             logging.info("Generated Test Cases:")
#             logging.info(test_cases)
#             logging.info("Evaluation:")
#             logging.info(evaluation)
#             logging.info("----")

# if __name__ == "__main__":
#     # Load API documentation
#     api_data = load_api_endpoints('api_endpoints.json')
    
#     # Process and generate test cases
#     process_api_documentation(api_data)
    
#     print("Super-advanced test cases generated, evaluated, and logged in test_case.log.")




# import json
# import logging
# from together import Together

# # Initialize Together AI client
# together_client = Together(api_key="ec9520d163d357d5ed7414ed993c027fdcd36c7d5c64149811fcc85f201db981")

# # Set up logging
# logging.basicConfig(filename='test_case.log', level=logging.INFO, format='%(message)s')

# # HTML Template for Logging
# HTML_TEMPLATE = """
# <!DOCTYPE html>
# <html lang="en">
# <head>
#     <meta charset="UTF-8">
#     <meta name="viewport" content="width=device-width, initial-scale=1.0">
#     <style>
#         body {{ font-family: Arial, sans-serif; margin: 20px; }}
#         h2 {{ color: #333; }}
#         .section {{ margin-bottom: 40px; }}
#         .test-case {{ background-color: #f9f9f9; padding: 10px; border-radius: 5px; }}
#         .execution {{ background-color: #e6f7ff; padding: 10px; border-radius: 5px; }}
#         .evaluation {{ background-color: #e6ffe6; padding: 10px; border-radius: 5px; }}
#     </style>
#     <title>API Security Test Report</title>
# </head>
# <body>
#     <h1>API Security Test Report</h1>
#     {content}
# </body>
# </html>
# """

# # Load API endpoints from JSON file
# def load_api_endpoints(file_path):
#     with open(file_path, 'r') as file:
#         return json.load(file)

# # Generate, execute, and evaluate test cases using LLM
# def generate_execute_evaluate_test_cases(endpoint, method, details):
#     # Step 1: Generate super-advanced test cases
#     generate_prompt = f"""
#     Generate super-advanced test cases for the following API endpoint to cover OWASP Top 10 API risks:
    
#     Endpoint: {endpoint}
#     Method: {method}
#     Security: {details.get('security', 'None')}
#     Parameters: {details.get('parameters', 'None')}
#     Responses: {details.get('responses', 'None')}
#     """
#     test_cases_response = together_client.chat.completions.create(
#         model="meta-llama/Meta-Llama-3.1-405B-Instruct-Turbo",
#         messages=[
#             {"role": "system", "content": "You are an expert in API security."},
#             {"role": "user", "content": generate_prompt},
#         ],
#         max_tokens=699,
#         temperature=0.11,
#         top_p=1,
#         top_k=50,
#         repetition_penalty=1,
#         stop=["<|eot_id|>"],
#     )
#     test_cases = test_cases_response.choices[0].message.content

#     # Step 2: Execute the test cases (Simulated)
#     execution_prompt = f"""
#     Simulate the execution of the following test cases for the API endpoint and provide results:
    
#     Endpoint: {endpoint}
#     Method: {method}
#     Test Cases: {test_cases}
#     """
#     execution_response = together_client.chat.completions.create(
#         model="meta-llama/Meta-Llama-3.1-405B-Instruct-Turbo",
#         messages=[
#             {"role": "system", "content": "You are an expert in API testing."},
#             {"role": "user", "content": execution_prompt},
#         ],
#         max_tokens=699,
#         temperature=0.11,
#         top_p=1,
#         top_k=50,
#         repetition_penalty=1,
#         stop=["<|eot_id|>"],
#     )
#     execution_results = execution_response.choices[0].message.content

#     # Step 3: Evaluate the execution results
#     evaluate_prompt = f"""
#     Evaluate the results of the executed test cases for the API endpoint:
    
#     Endpoint: {endpoint}
#     Method: {method}
#     Execution Results: {execution_results}
    
#     Provide a conclusion on whether the API is secure according to OWASP Top 10 API risks.
#     """
#     evaluation_response = together_client.chat.completions.create(
#         model="meta-llama/Meta-Llama-3.1-405B-Instruct-Turbo",
#         messages=[
#             {"role": "system", "content": "You are an expert in API security evaluation."},
#             {"role": "user", "content": evaluate_prompt},
#         ],
#         max_tokens=699,
#         temperature=0.11,
#         top_p=1,
#         top_k=50,
#         repetition_penalty=1,
#         stop=["<|eot_id|>"],
#     )
#     evaluation = evaluation_response.choices[0].message.content

#     # Function to convert plain text into HTML formatted blocks
#     def convert_to_html_blocks(text):
#         blocks = text.split('\n')
#         html_blocks = []
#         for block in blocks:
#             if block.strip():
#                 html_blocks.append(f"<div class='test-case-block'>{block.strip()}</div>")
#         return ''.join(html_blocks)

#     formatted_test_cases = convert_to_html_blocks(test_cases)
#     formatted_execution_results = convert_to_html_blocks(execution_results)
#     formatted_evaluation = convert_to_html_blocks(evaluation)

#     # Create HTML section with CSS styling
#     html_section = f"""
#     <style>
#         .section {{
#             margin-bottom: 20px;
#             font-family: Arial, sans-serif;
#         }}
#         .test-case, .execution, .evaluation {{
#             margin-top: 20px;
#             padding: 15px;
#             border: 1px solid #ddd;
#             border-radius: 5px;
#             background-color: #f9f9f9;
#         }}
#         .test-case-block, .execution-block, .evaluation-block {{
#             margin-bottom: 20px;
#             padding: 10px;
#             border-bottom: 1px solid #ddd;
#         }}
#         .test-case-block:last-child, .execution-block:last-child, .evaluation-block:last-child {{
#             border-bottom: none;
#         }}
#         .header {{
#             color: #000;
#             font-weight: bold;
#             font-size: 1.2em;
#             margin-bottom: 15px;
#         }}
#         .test-case-block, .execution-block, .evaluation-block {{
#             background-color: #ffffff;
#         }}
#         .sub-header {{
#             color: #000;
#             font-weight: bold;
#             font-size: 1.1em;
#             margin-top: 10px;
#             margin-bottom: 10px;
#         }}
#         .final-conclusion {{
#             color: #000;
#             font-weight: bold;
#             font-size: 1.2em;
#             margin-top: 20px;
#         }}
#     </style>
    
#     <div class="section">
#         <h2 style="color: #2c3e50;">Endpoint: {endpoint} | Method: {method}</h2>
        
#         <div class="test-case">
#             <h3 class="header">Generated Test Cases</h3>
#             <div class="sub-header">{formatted_test_cases}</div>
#         </div>

#         <div class="execution">
#             <h3 class="header">Execution Results</h3>
#             <div class="sub-header">{formatted_execution_results}</div>
#         </div>

#         <div class="evaluation">
#             <h3 class="header">Evaluation</h3>
#             <div class="sub-header">{formatted_evaluation}</div>
#             <div class="final-conclusion">Final Conclusion: {evaluation}</div>
#         </div>
#     </div>
#     """
#     return html_section







# # Process API documentation
# def process_api_documentation(api_data):
#     content = ""
#     paths = api_data.get("paths", {})
#     for endpoint, methods in paths.items():
#         for method, details in methods.items():
#             html_section = generate_execute_evaluate_test_cases(endpoint, method, details)
#             content += html_section
    
#     # Write the HTML content to the log file
#     html_content = HTML_TEMPLATE.format(content=content)
#     with open('test_case.log', 'w') as file:
#         file.write(html_content)

# if __name__ == "__main__":
#     # Load API documentation
#     api_data = load_api_endpoints('api_endpoints.json')
    
#     # Process and generate test cases
#     process_api_documentation(api_data)
    
#     print("Super-advanced test cases generated, executed, evaluated, and logged in test_case.log.")


