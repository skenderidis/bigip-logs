# Integrating BIGIP with Logstash (running in a docker)

Steps will be provided on how to deploy all of the software in a Docker environment using Docker Compose. It is assumed that Docker is already installed and configured on the system.

### Clone the repo

Clone this repo to your local machine using `https://github.com/skenderidis/bigip-logs` and switch the working directory to be `bigip-logs`

```shell
git clone https://github.com/f5devcentral/nap-policy-management
cd bigip-logs
```

### Install Logstash using docker-compose

```shell
TZ=Asia/Dubai && docker-compose up -d
```

NOTES:
>  - Change the timezone used in the docker containers by altering the inline environment variable in the command above accordingly to your location. A list of TZ Database Names can be found [here](https://en.wikipedia.org/wiki/List_of_tz_database_time_zones).
>  - The TCP port that Logstash is listening to is 8515. This can be changed from the `docker-compose.yaml` file. 


### Configuring index for Elastic (Optional, only if you are using ELK)

Create index templates for on Elasticsearch

```shell
curl -d "@index-template.json" -H 'Content-Type: application/json' -X PUT 'http://ELASTIC_IP:9200/_index_template/bigip-waf-logs'
```
Expected Response: `{"acknowledged":true}`


### Configure Logging profile for BIGIP

On BIGIP go to Event Logs -> Logging Profiles and create a new profile.
Select the following variables:
- Application Security:	Enabled
- Storage Destination: Remote Storage
- Logging Format: Comma-Separated Values
- Protocol: TCP
- Storage Format: 
```
date_time="%date_time%",is_truncated="%is_truncated%",ip_client="%ip_client%",vs_name="%vs_name%",dest_port=%dest_port%,attack_type="%attack_type%",blocking_exception_reason="%blocking_exception_reason%",method="%method%",policy_name="%policy_name%",protocol="%protocol%",request_status="%request_status%",response_code=%response_code%,severity="%severity%",sig_cves="%sig_cves%",sig_ids="%sig_ids%",sig_names="%sig_names%",sig_set_names="%sig_set_names%",sub_violations="%sub_violations%",support_id="%support_id%",threat_campaign_names="%threat_campaign_names%",unit_hostname="%unit_hostname%",uri="%uri%",violation_rating="%violation_rating%",x_forwarded_for_header_value="%x_forwarded_for_header_value%",violations="%violations%",violation_details="%violation_details%",request="%request%"
```
- Maximum Entry Length: 10K


### Modify logstash.conf
Open the logstash.conf and modify the output plugin for the configuration. If you are using elasticseach you just need to change the hostname/IP of Elastiseach, but if you are using another SIEM solution you need to modify the output accordingly. More information on logstash output plugins can be found on (https://www.elastic.co/guide/en/logstash/current/output-plugins.html)

Currently the output configuration is as follows:

```
output {
  if "decoded" in [tags] 
  {
    elasticsearch {
      hosts => ["elasticsearch:9200"]
      index => "waf-decoded-logs-%{+YYY.MM.dd}"
    }
  }
  else{
    elasticsearch {
      hosts => ["elasticsearch:9200"]
      index => "waf-logs-%{+YYY.MM.dd}"
    }
  }
}
```


## Support

Please open a GitHub issue for any problem or enhancement you need.

