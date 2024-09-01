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

       
    except Exception as e:
        logging.error(f"Main execution error: {e}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="API Security Test Script")
    parser.add_argument('api_file', type=str, help='Path to the API endpoints JSON file')
    args = parser.parse_args()

    main(args.api_file)


# Replace 'together_client' with the appropriate OpenAI API client or similar
# Initialize your API client here (example)
# together_client = OpenAI(api_key='YOUR_API_KEY')


def generate_execute_evaluate_test_cases(endpoint, method, details):
    # Step 1: Generate super-advanced test cases
    generate_prompt = f"""
    Generate super-advanced test cases for the following API endpoint to cover the following OWASP Top 10 API risks:
    Security misconfiguration,
    Server-side request Forgery,
    Broken object Level Authorization,
    Unrestricted resource consumption,
    Unsafe consumption of APIs,
    Unrestricted access to sensitive business flows,
    Api2 broken authentication,
    Broken authentication,
    Api5:2023 broken function level authorization:
    
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
            {"role": "system", "content": "You are an expert in API testing and expert in executing the super advance test cases like real security team."},
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

#     # Prepare the content for the log file
#     log_content = f"""
#     Endpoint: {endpoint}
#     Method: {method}
    
#     Test Cases:
#     {test_cases}
    
#     Execution Results:
#     {execution_results}
    
#     Evaluation:
#     {evaluation}
#     """

#     return log_content

# # # Process API documentation
# # def process_api_documentation(api_data):
# #     log_content = ""
# #     paths = api_data.get("paths", {})
# #     for endpoint, methods in paths.items():
# #         for method, details in methods.items():
# #             log_section = generate_execute_evaluate_test_cases(endpoint, method, details)
# #             log_content += log_section + "\n\n" + "="*50 + "\n\n"
    
# #     # Write the log content to the file
# #     with open('llm_test.log', 'w') as file:
# #         file.write(log_content)

# # def load_api_endpoints(file_path):
# #     with open(file_path, 'r') as file:
# #         return json.load(file)

# # if __name__ == "__main__":
# #     # Load API documentation
# #     api_data = load_api_endpoints('api_endpoints.json')
    
# #     # Process and generate test cases
# #     process_api_documentation(api_data)
    
# #     print("Super-advanced test cases generated, executed, evaluated, and logged in llm_test.log.")
# # # Process API documentation
# def process_api_documentation(api_data):
#     content = ""
#     paths = api_data.get("paths", {})
#     for endpoint, methods in paths.items():
#         for method, details in methods.items():
#             html_section = generate_execute_evaluate_test_cases(endpoint, method, details)
#             content += html_section
    
#     # Write the HTML content to the report file
#     with open('llm_test.html', 'w') as file:
#         file.write(content)

# def load_api_endpoints(file_path):
#     with open(file_path, 'r') as file:
#         return json.load(file)

# if __name__ == "__main__":
#     # Load API documentation
#     api_data = load_api_endpoints('api_endpoints.json')
    
#     # Process and generate test cases
#     process_api_documentation(api_data)
    
#     print("Super-advanced test cases generated, executed, evaluated, and logged in llm_test.html.")

    evaluation = evaluation_response.choices[0].message.content

    # Prepare the content for the HTML file
    html_content = f"""
    <html>
    <head>
        <title>API Test Cases Report</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; }}
            .section {{ margin-bottom: 40px; padding: 20px; border: 1px solid #ddd; border-radius: 8px; }}
            .heading {{ font-weight: bold; color: #333; margin-bottom: 10px; }}
            .content {{ margin-bottom: 20px; }}
            .content h2 {{ margin-top: 0; color: #555; }}
            .content p {{ margin: 0; padding: 0; white-space: pre-wrap; }}
        </style>
    </head>
    <body>
        <h1>API Test Cases Report</h1>
        <div class="section">
            <div class="heading">Endpoint: {endpoint}</div>
            <div class="heading">Method: {method}</div>
            <div class="content">
                <h2>Test Cases:</h2>
                <p>{test_cases}</p>
            </div>
            <div class="content">
                <h2>Execution Results:</h2>
                <p>{execution_results}</p>
            </div>
            <div class="content">
                <h2>Evaluation:</h2>
                <p>{evaluation}</p>
            </div>
        </div>
    </body>
    </html>
    """
    return html_content

def process_api_documentation(api_data):
    content = ""
    paths = api_data.get("paths", {})
    for endpoint, methods in paths.items():
        for method, details in methods.items():
            html_section = generate_execute_evaluate_test_cases(endpoint, method, details)
            content += html_section + "<hr>"

    # Write the HTML content to the report file
    with open('llm_test.html', 'w') as file:
        file.write(content)

def main(api_file):
    try:
        # Perform ZAP Scan
        alerts = perform_zap_scan(api_file)

        # Load API Endpoints
        api_endpoints = load_api_endpoints(api_file)

        # Process and generate test cases
        process_api_documentation(api_endpoints)

        print("Super-advanced test cases generated, executed, evaluated, and logged in llm_test.html.")
    except Exception as e:
        logging.error(f"Main execution error: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="API Security Test Script")
    parser.add_argument('api_file', type=str, help='Path to the API endpoints JSON file')
    args = parser.parse_args()

    main(args.api_file)






















