import os, sys, requests, json, logging, csv, argparse
from veracode_api_signing.plugin_requests import RequestsAuthPluginVeracodeHMAC
scan_name='TEST_NEW'
app_name="{scan_name}"
app='REST API Testing'
api_base = "https://api.veracode.com/was/configservice/v1/"
verifyCert=True

api_id = os.getenv("API_ID")
api_secret = os.getenv("API_KEY")

class DynamicAnalysis:
    headers = {"User-Agent": "DynamicAnalysis"}

    def get_data_request(self, url, filename="JsonData", export=False):
        try:
            log.debug("Sending request to %s", url)
            response = requests.get(url, auth=RequestsAuthPluginVeracodeHMAC(), headers=self.headers, verify=verifyCert)
            if response.ok:
                return response.json()
            else:
                log.error("Request for %s failed with %s code", filename, response.text)
        except requests.RequestException as e:
            log.error("Request for %s failed.", filename)

    def get_analysis(self, scan_name, export=False, recurse=True):
        log.info("Exporting scan spec data for scan named '%s'", scan_name)
        api_base="https://api.veracode.com/was/configservice/v1/analyses"
        try:
            arg1 = "name=" + scan_name
            response = requests.get(api_base+"?"+arg1, auth=RequestsAuthPluginVeracodeHMAC(), headers=self.headers, verify=verifyCert)
            print(response.json)
            analysis_summary = response.json()
            if response.ok:
                if (recurse): 
                    url = analysis_summary["_embedded"]["analyses"][0]["_links"]["scans"]["href"]
                    scan_details = self.get_data_request(url, "Exported_Detailed_Scan", export)
                    url = analysis_summary["_embedded"]["analyses"][0]["_links"]["self"]["href"]
                    analysis = self.get_data_request(url, "Exported_Analysis", export)
                    url = analysis_summary["_embedded"]["analyses"][0]["_links"]["latest_occurrence"]["href"]
                    latest_occurrence = self.get_data_request(url, "Exported_Detailed_Scan", export)
                    analysis_occurrence_id  = latest_occurrence["analysis_occurrence_id"]
                    base_url="https://api.veracode.com/was/configservice/v1"
                    url = "%s/analysis_occurrences/%s/scan_occurrences" % (base_url, analysis_occurrence_id)
                    detailed_scan_occurrence = self.get_data_request(url, "Exported_DetailedScanOccurrence", export)
                    summary = detailed_scan_occurrence["_embedded"]["scan_occurrences"][0]["summary"]
                    log.debug("Summary: %s", json.dumps(summary, sort_keys=True, indent=0))
                    url = analysis_summary["_embedded"]["analyses"][0]["_links"]["audits"]["href"]
                    audit_data = self.get_data_request(url, "Exported_Audit_Data", export)
                    return (analysis_summary, scan_details, analysis, latest_occurrence, audit_data)
                else:
                    return (analysis_summary)
            else:
                log.error("Scan Request failed with %s code", response.text)
                return
        except requests.RequestException as e:
            log.error("Scan Request data failed.")

    def scan_now(self, scan_name):
        (analysis_summary, scan_details, analysis_details, latest_occurrence, audit_data) = self.get_analysis(scan_name, export=False, recurse=True)
        scan_id = scan_details["_embedded"]["scans"][0]["scan_id"]
        current_schedule = analysis_details["schedule"]
        url = analysis_details["_links"]["self"]["href"]
        schedule_data = {"schedule": {"now": True, "duration": { "length": 1, "unit": "DAY" }}}
        log.debug("New schedule data: %s", schedule_data)
        url = url + "?method=PATCH"
        log.info("Updating scan to %s", url)
        log.debug("PUT Body: " + json.dumps(schedule_data, sort_keys=True, indent=4))
        response = requests.put(url, auth=RequestsAuthPluginVeracodeHMAC(), headers=self.headers, json=schedule_data, verify=verifyCert)
        if response.ok:
            log.info("Successful response: %s", str(response))
            return response
        else:
            log.error("Scan schedule Request failed with %s code: %s", response.status_code, response.text)
            return

if __name__ == "__main__":

    log = logging.getLogger(app_name)
    log_format = '%(asctime)-15s %(levelname)s: %(message)s'
    logging.basicConfig(format=log_format, datefmt='%Y/%m/%d-%H:%M:%S')
    log.setLevel(logging.INFO)
    log.setLevel(logging.DEBUG)
    a = DynamicAnalysis()
    #scan_name='Findings DAST'
    scans =a.scan_now(scan_name)
