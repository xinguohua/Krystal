# Krystal Framework
KRYSTAL is a modular framework for tactical attack discovery in audit data. The proposed framework integrates a variety of attack discovery mechanisms and takes advantage of its semantic model to include internal and external knowledge in the analysis. Figure 1 gives an overview of the KRYSTAL attack discovery framework which consists of three main parts, i.e., (i) provenance graph building, (ii) threat detection and alerting, and (iii) attack graph and scenario reconstruction.

![ ](https://raw.githubusercontent.com/kabulkurniawan/Krystal/main/architecture-latest3.png)<p align="center"> **Figure 1** Krystal Architecture.

KRYSTAL imports each log event in sequence from potentially heterogeneous hosts (e.g., Linux, Windows, FreeBSD), i.e., in an online mode. It then generates an RDF-based provenance graph, taking advantage of the defined ontology and background knowledge in the Provenance Graph Building module. Subsequently, a number of threat detection and alerting approaches can be applied on the provenance graphs, including (i) tag propagation, (ii) attenuation & decay, and (iii) signature-based detection based on Indicators of Compromise (IoCs). These techniques are provided by the Threat Detection & Alerting module. The Attack Graph Reconstruction module then facilitates (offline) attack graph generation via Backward-forward chaining and attack pattern matching via Graph Querying over the provenance graph. 

## Pre Installation and Configuration

### TripleStore Installation
To be able to store the output data and perform data analyze, i.e. for Attack Reconstruction, A triple store with a built-in SPARQL query interface and visualization is need it. For example GraphDB, we can follow this [installation page](https://graphdb.ontotext.com/documentation/standard/installation.html) for further GraphDB installation instruction. 

### Configuration File
There are some configuration should be made prior running the application. Please take a look at the configuration file ([config.yaml](https://github.com/sepses/Krystal/blob/main/config.yaml)).


```bash
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

confidential-dir: #Setting for any confidential directories
 - /etc/passwd 
 - /var/log
 - /etc/shadow
 - /documents/

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

## Dataset for Evaluation
we used well-established datasets from red vs. blue team adversarial engagements produced as part of the third Transparent Computing (TC) program organized by [DARPA](https://drive.google.com/drive/folders/1QlbUFWAGq3Hpl8wVdzOdIoZLFxkII4EK). The datasets are organized into five categories, namely Cadets, Trace, Theia, FiveDirections and ClearScope. We include several examples of the dataset under the directory [experiment/input](https://github.com/sepses/Krystal/tree/main/experiment/input).

## Run the Code

This project can be setup by cloning and installing and running it as follows:

```bash
$ git clone https://github.com/sepses/Krystal.git
$ cd Krystal
$ mvn clean install
```
To run the compiled project: 

```bash
$ java -jar ./target/SimpleLogProvenance-0.0.1-SNAPSHOT-jar-with-dependencies.jar
```
The log processing will take a couple of time depending the size of the input data. After processing the input data, several output files will be produced, such as: the dependency (provenance) graphs (in RDF/.ttl file), the alert data (in RDF-star/.ttl), and the compressed version of the RDF graph (in .hdt). See the example process below:

```bash
$ java -jar .\target\SimpleLogProvenance-0.0.1-SNAPSHOT-jar-with-dependencies.jar
Start running ubuntu14 parser...
processing file: cadets100000.json
reading from line : 1
parsing 1 of 100000 finished in 11293
the rest is less than 100000 which is 3
0
finish processing file:experiment/input/cadets/cadets100000.json
generate alert from community ruleexperiment/rule/
number of events :94050
Statictics:
http://w3id.org/sepses/resource/rule/corrupt-file-rule : 6
http://w3id.org/sepses/resource/rule/change-permission-rule : 20
http://w3id.org/sepses/resource/sigma/sigma-444ade84-c362-4260-b1f3-e45e20e1a905 : 1
Save model to rdf file...Done!
Save model to rdf file...Done!
Save model rdf to hdt....Done!
```

We provided several example RDF output (in RDF and .HDT) file under the directory [experiment/output](https://github.com/sepses/Krystal/tree/main/experiment/output). 


## Analyzing / Querying the Data
The resulting output data (the RDF data) can already be queried for analysis e.g. for root cause analysis, attack graph reconstruction (via graph query or forward chaining technique), etc. The directory [experiment/query](https://github.com/sepses/Krystal/tree/main/experiment/query) contains several example queries that can be used for analysis.

## License

The Krystal Framework is written by [Kabul Kurniawan](https://kabulkurniawan.github.io/) released under the [MIT license](http://opensource.org/licenses/MIT).

