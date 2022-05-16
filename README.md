# KRYSTAL: Knowledge Graph-based Framework for Tactical Attack Discovery in Audit Data
## What is Krystal?
KRYSTAL is a modular framework for tactical attack discovery in audit data. The proposed framework integrates a variety of attack discovery mechanisms and takes advantage of its semantic model to include internal and external knowledge in the analysis. 
## Krystal Components

![ ](https://raw.githubusercontent.com/kabulkurniawan/Krystal/main/architecture-latest3.png)<p align="center"> **Figure 1** Krystal Architecture.

Figure 1 gives an overview of the KRYSTAL attack discovery framework which consists of three main components, i.e., *(i) provenance graph building, (ii) threat detection and alerting, and (iii) attack graph and scenario reconstruction*. Each component may leverage background knowledge to contextualize, link, and enrich the graph over both internal and external cybersecurity information (e.g. IT Assets, Vulnerabilities, CTI, etc.)

KRYSTAL imports each log event (currently Audit Data) in sequence from potentially heterogeneous hosts (e.g., Linux, Windows, FreeBSD), i.e., in an online mode. It then generates an RDF-based provenance graph, taking advantage of the defined ontology (i.e. [Krystal Ontology](https://sepses.ifs.tuwien.ac.at/vocab/event/log/index-en.html)) and background knowledge (e.g. [SEPSES CS-KG](http://sepses.ifs.tuwien.ac.at/)) in the *"Provenance Graph Building"* module. Subsequently, several threat detection and alerting approaches can be applied to the provenance graphs in the *"Threat Detection and Alerting Module"*, including:
 (i) tag propagation, 
 (ii) attenuation & decay, and 
 (iii) signature-based detection based on Indicators of Compromise (IoCs), e.g. through [Sigma Rule](https://github.com/SigmaHQ/sigma).
 *The "Attack Graph Reconstruction"* module then facilitates (offline) attack graph generation via several graph construction techniques, including 
 (i) Backward-forward chaining and 
 (ii) attack pattern matching via Graph Querying 
 over the provenance graph. 

## Requirements
Krystal Framework is built based on the Java Application Platform that can be deployed in most OS with a JVM. Therefore, it requires a JVM to be installed on the system beforehand. Please follow this [documentation](https://www.oracle.com/java/technologies/downloads/) to download and run the JVM.
Furthermore, An RDF-graph database with a built-in SPARQL Query will also be required to store the output RDF data, perform data/attack analysis, i.e. *attack graph construction and graph queries* as well as to *visualize* the resulting graph. For example, we used Stardog and Graph DB for example during our experiment. For GraphDB Installation, please follow this [installation page](https://graphdb.ontotext.com/documentation/standard/installation.html). For Stardog, please follow this [documentation](https://docs.stardog.com/). 

## Installation and Configuration

## Installation

This project can be set up by cloning and installing and running it as follows:

```bash
$ git clone https://github.com/sepses/Krystal.git
$ cd Krystal
$ mvn clean install
```

### Configuration
Some configurations should be made prior to running the application. We include some explanations directly in the configuration comments. Please take a look at it ([config.yaml](https://github.com/sepses/Krystal/blob/main/config.yaml)). 


```bash
#basic configuration
input-dir: experiment/input/cadets/ #log-sources directory, see the dataset example (cadets,trace,theia,fivedirections)
output-dir: experiment/output/ #output directory, any output file (.rdf/hdt) will be stored in this folder  
tdb-dir: experiment/tdb #Jena TDB directory, this directory is needed for storing TDB temporary file
ontology: experiment/ontology/log-ontology.ttl #Krystal Ontology location
rule-dir : experiment/rule/ #rules should be stored in this directory i.e. Sigma Rule (see the example)
rule-dir-win : experiment/rule_win/ #special rules directory for windows i.e. Sigma Rule for windows  (see the example)
os-platform: ubuntu14 #OS platform, (ubuntu14 for cadets, trace ; freebsd for theia ; windows for fivedirections)
triple-store: graphdb #Triple Store type (graphdb, virtuoso)
sparql-endpoint: http://localhost:7200/repositories/cadets #endpoint for storing rdf output to triple Store
namegraph: http://w3id.org/sepses/graph/cadets #namegraph of the RDF output / filename of the output
line-number: 100000 #minimum log line number to be processed (minimum 1)
decay-rule: yes # Option to perform decay (yes/no)
live-store: no #Option for storing output data to the triplestore continuously (yes/no)
backup-file: yes #Save the output in RDF and .HDT (yes/no)

#CONFIDENTIAL DIRECTIORIES: list of of any confidential directories. These will be used as  initialization of confidentiality score in tag-propagation technique during provenance graph building)
confidential-dir: #please add any other confidential directories
 - /etc/passwd 
 - /var/log
 - /etc/shadow
 - /documents/

#AUDIT EVENTS: list of any events from audit data that need to be included in the provenance graph building. 
field-filter: #Event filter for log processing (filter only the uncommented events (event with #))
 #- EVENT_FORK
 - EVENT_EXIT
 - EVENT_MPROTECT
 - EVENT_LOGIN
 #- EVENT_CLONE
 #- EVENT_LOADLIBRARY
 #- EVENT_EXECUTE
 - EVENT_ACCEPT
 - EVENT_RECVMSG
 - EVENT_SENDMSG
 ...
```

### Running the Application:

To run the compiled project: 

```bash
$ java -jar ./target/SimpleLogProvenance-0.0.1-SNAPSHOT-jar-with-dependencies.jar
```
The log processing will take a couple of times depending on the size of the input data. After processing the input data, several output files will be produced, such as the dependency (provenance) graphs (in RDF/.ttl file), the alert data (in RDF-star/.ttl), and the compressed version of the RDF graph (in .hdt). We provided several example RDF output (in RDF and .HDT) file under the directory [experiment/output](https://github.com/sepses/Krystal/tree/main/experiment/output). 


## Analyzing / Querying the Graph
The resulting output data (the RDF data) can already be queried for analysis e.g. for root cause analysis, attack graph reconstruction (via graph query or forward chaining technique), etc. The directory [experiment/query](https://github.com/sepses/Krystal/tree/main/experiment/query) contains several example queries that can be used for analysis.

## Dataset for Testing and Evaluation
Krystal currently only supports audit data, especially from well-established datasets from red vs. blue team adversarial engagements produced as part of the third Transparent Computing (TC) program organized by [DARPA](https://drive.google.com/drive/folders/1QlbUFWAGq3Hpl8wVdzOdIoZLFxkII4EK). The datasets are organized into five categories, namely Cadets, Trace, Theia, FiveDirections, and ClearScope. We include several examples of the dataset under the directory [experiment/input](https://github.com/sepses/Krystal/tree/main/experiment/input).


## Example Demo
We provided an example demo [here](https://github.com/sepses/Krystal/Demo.md). It includes a tutorial for building a provenance graph from threat detection, applying threat detections using several techniques as well as performing analysis e.g. attack graph construction and visualization. 

## License

The Krystal Framework is written by [Kabul Kurniawan](https://kabulkurniawan.github.io/) and released under the [MIT license](http://opensource.org/licenses/MIT).

