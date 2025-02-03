# CrowdStrike Falcon Discover Add-on for Splunk

This Splunk Technical Add-on allows you to fetch data from the CrowdStrike Falcon® Discover module. The following inputs are supported:

- **CrowdStrike Falcon Discover Application data:** Monitor applications discovered on your agents

## Setup & Configuration

### Where to install this add-on (Splunk Enterprise)

| Splunk platform instance type | Supported | Required    | Comments |
| ----------------------------- | --------- | --------    | -------- |
| Search Heads                  | Yes       | Yes         | Only the source type is required, but you can install the whole TA without input configuration on search heads |
| Indexers                      | Yes       | Conditional | I recommend to use Heavy Forwarders to collect data, but an Indexer can also be used. If you don't run the input on an indexer, don't install this TA to Indexers! |
| Heavy Forwarders              | Yes       | Conditional | It's recommended to run inputs on this instance! |
| Universal Forwarders          | No        | No          | |

> 📝 Single-instance (standalone) and Splunk Cloud deployments are supported as well!

### CrowdStrike Falcon Configuration

The Add-on fetches data from the CrowdStrike Falcon REST API. You have to add a new API client with at least the following API scopes:

- Hosts
- Discover

Copy the **client ID and secret**. You will need it during the TA configuration.

### Technical Add-on Configuration

The Setup of this TA is very straightforward. Here are the required steps:

- Install the TA on your Splunk instance(s) according to the table above (*Where to install this add-on (Splunk Enterprise)*)
- Open the **CrowdStrike Falcon Discover Add-on for Splunk** App

  ![Navigation Bar Entry](/screenshots/nav_bar.jpg "Navigation Bar Entry")

- Switch to **Configuration** and add a new **Account**

  ![Add Account UI](/screenshots/add_account.jpg "Add Account UI")

- Switch to **Inputs** and create new inputs according to your needs.

  - **Application Input:**
    
    ![Application Input UI](/screenshots/application_input.jpg "Application Input UI")
    
    This input fetches application data for hosts matching an optional FQL filter. See the screenshot above for a full list of configuration options.

- Verify that the input is working by searching for the data! If you don't see anything, have a look at the **Troubleshooting** section.

## Troubleshooting

The TA writes logs into `_internal`. You can use the following search for troubleshooting/monitoring purposes:

```
index="_internal" sourcetype="crowdstrike:discover:application:talog"
```

Optionally, raise the Log Level on the App Configuration page:

 ![Logging UI](/screenshots/logging.jpg "Logging UI")

## Contribution/Development Information

This project uses Docker Compose to spin up a full Splunk Enterprise development environment.

- Put your Splunk developer license in the root of this repository in a file called `splunk.lic`

- Start the Docker instance: `docker compose up [-d]`

That's it. You can now start configuring the add-on in Splunk Web and develop whatever you like.

**Hint:** The Splunk instance is pre-configured with an index called `crowdstrike`. You can use it to store data.

This project is actually hosted in GitLab and synced to GitHub, but you can still contribute to this project in GitHub of course!
