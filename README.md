# KRYSTAL: Knowledge Graph-based Framework for Tactical Attack Discovery in Audit Data
## What is Krystal?
KRYSTAL is a modular framework for tactical attack discovery in audit data. The proposed framework integrates a variety of attack discovery mechanisms and takes advantage of its semantic model to include internal and external knowledge in the analysis.

KRYSTAL 是一个用于在审计数据中发现战术攻击的模块化框架。该框架集成了多种攻击发现机制，并利用其语义模型将内部和外部知识纳入分析。
## Krystal Components

![ ](https://raw.githubusercontent.com/kabulkurniawan/Krystal/main/architecture-latest3.png)<p align="center"> **Figure 1:** Krystal Architecture.

Figure 1 gives an overview of the KRYSTAL attack discovery framework which consists of three main components, i.e., *(i) provenance graph building, (ii) threat detection and alerting, and (iii) attack graph and scenario reconstruction*. Each component may leverage background knowledge to contextualize, link, and enrich the graph over both internal and external cybersecurity information (e.g. IT Assets, Vulnerabilities, CTI, etc.)

图 1 概述了 KRYSTAL 攻击发现框架，该框架由三个主要组件组成，即*(i) 来源图构建、(ii) 威胁检测和警报以及 (iii) 攻击图和场景重建*。每个组件都可以利用背景知识来情境化、链接和丰富内部和外部网络安全信息（例如 IT 资产、漏洞、CTI 等）的图表。

KRYSTAL imports each log event (currently Audit Data) in sequence from potentially heterogeneous hosts (e.g., Linux, Windows, FreeBSD), i.e., in an online mode. It then generates an RDF-based provenance graph, taking advantage of the defined ontology (i.e. [Krystal Ontology](https://sepses.ifs.tuwien.ac.at/vocab/event/log/index-en.html)) and background knowledge (e.g. [SEPSES CS-KG](http://sepses.ifs.tuwien.ac.at/)) in the *"Provenance Graph Building"* module. Subsequently, several threat detection and alerting approaches can be applied to the provenance graphs in the *"Threat Detection and Alerting Module"*, including:
 (i) tag propagation, 
 (ii) attenuation & decay, and 
 (iii) signature-based detection based on Indicators of Compromise (IoCs), e.g. through [Sigma Rules](https://github.com/SigmaHQ/sigma).
 *The "Attack Graph Reconstruction"* module then facilitates (offline) attack graph generation via several graph construction techniques, including 
 (i) Backward-forward chaining and 
 (ii) attack pattern matching via Graph Querying 
 over the provenance graph. 

KRYSTAL 以在线模式从可能异构的主机（例如 Linux、Windows、FreeBSD）按顺序导入每个日志事件（当前为审计数据）。然后，它会利用 *“起源图构建”* 模块中定义的本体（即 [Krystal Ontology](https://sepses.ifs.tuwien.ac.at/vocab/event/log/index-en.html)）和背景知识（例如 [SEPSES CS-KG](http://sepses.ifs.tuwien.ac.at/)）生成基于 RDF 的起源图。随后，可将多种威胁检测和警报方法应用于“威胁检测和警报模块”中的来源图，包括：
(i) 标签传播，
(ii) 衰减和衰减，以及
(iii) 基于入侵指标 (IoC) 的基于签名的检测，例如通过 [Sigma 规则](https://github.com/SigmaHQ/sigma)。
*“攻击图重建”* 模块随后通过多种图形构建技术促进（离线）攻击图生成，包括
(i) 后向-前向链接和
(ii) 通过对来源图进行图形查询进行攻击模式匹配。

## Requirements
The Krystal Framework is built based on the Java Application Platform, hence, it requires a JVM. Please follow this [documentation](https://www.oracle.com/java/technologies/downloads/) to download and run the JVM.
Furthermore, an RDF-graph database with a built-in SPARQL Query Engine is also required to store the RDF data, perform data/attack analysis, i.e. *attack graph construction and graph queries*, as well as to *visualize* the resulting graphs. Krystal supports RDF triplestores such as [GraphDB](https://graphdb.ontotext.com/) -- follow the [installation page](https://graphdb.ontotext.com/documentation/standard/installation.html). Once the installation has completed, GraphDB can be accessed locally via your web browser at [http://localhost:7200](http://localhost:7200/). Krystal requires one repository to be created beforehand, please take a look at this [documentation](https://graphdb.ontotext.com/documentation/free/creating-a-repository.html#:~:text=the%20RDF4J%20console.-,Using%20the%20Workbench,Select%20GraphDB%20Free%20repository.).

Krystal 框架基于 Java 应用平台构建，因此需要 JVM。请按照此 [文档](https://www.oracle.com/java/technologies/downloads/) 下载并运行 JVM。
此外，还需要一个内置 SPARQL 查询引擎的 RDF-graph 数据库来存储 RDF 数据、执行数据/攻击分析（即 *攻击图构建和图查询*）以及 *可视化* 生成的图。Krystal 支持 RDF 三元组存储，例如 [GraphDB](https://graphdb.ontotext.com/) - 按照 [安装页面](https://graphdb.ontotext.com/documentation/standard/installation.html) 操作。安装完成后，
您可以通过 Web 浏览器在 [http://localhost:7200](http://localhost:7200/) 本地访问 GraphDB。 Krystal 需要预先创建一个存储库，请查看此[文档](https://graphdb.ontotext.com/documentation/free/creating-a-repository.html#:~:text=the%20RDF4J%20console.-,Using%20the%20Workbench,Select%20GraphDB%20Free%20repository.)。

## Dataset for Testing and Evaluation
Krystal currently only supports audit data, in particular we demonstrate it on the adversarial engagements produced as part of the third Transparent Computing (TC) program organized by [DARPA](https://drive.google.com/drive/folders/1QlbUFWAGq3Hpl8wVdzOdIoZLFxkII4EK). The datasets are organized into five categories, namely Cadets, Trace, Theia, FiveDirections, and ClearScope. We include several examples of the dataset under the directory [experiment/input](https://github.com/sepses/Krystal/tree/main/experiment/input).


Krystal 目前仅支持审计数据，具体来说，我们在 [DARPA](https://drive.google.com/drive/folders/1QlbUFWAGq3Hpl8wVdzOdIoZLFxkII4EK) 组织的第三次透明计算 (TC) 计划中产生的对抗性交战中展示了它。数据集分为五类，即 Cadets、Trace、Theia、FiveDirections 和 ClearScope。我们在目录 [experiment/input](https://github.com/sepses/Krystal/tree/main/experiment/input) 下包含了数据集的几个示例。
## Installation and Configuration

## Installation

This project can be set up by cloning and installing and running it as follows:

可以通过克隆、安装并运行来设置该项目，如下所示：
```bash
$ git clone https://github.com/sepses/Krystal.git
$ cd Krystal
$ mvn clean install
```

### Configuration
In the following, we show configuration options with some explanations. Take a look at ([config.yaml](https://github.com/sepses/Krystal/blob/main/config.yaml)). 


下面，我们展示一些配置选项并进行解释。请查看 ([config.yaml](https://github.com/sepses/Krystal/blob/main/config.yaml))
```bash
#----------------------------- BASIC CONFIGURATION --------------------------------------
#Log-sources input directory, see the dataset example (cadets,trace,theia,fivedirections) 
#Log-sources输入目录，参见数据集示例（cadets、trace、theia、fivedirections）
input-dir: experiment/input/cadets/

#Minimum log line number to be processed (minimum 1)
#需要处理的最小日志行数（最小1）
line-number: 100000

#Save the output in RDF and .HDT (true/false)
backup-file: true

#Output directory, any output file (.rdf/hdt) will be stored in this folder 
#将输出保存在 RDF 和 .HDT 中（真/假）
output-dir: experiment/output/

#----------------------------- TARGETED TRIPLE STORE AND NAMEGRAPH ------------------------
#This option requires a triplestore (we used GraphDB)
#for GraphDB, Krystal requires a repository to be created beforehand
#Option for storing output data to the triplestore (true/false)

#----------------------------- 目标三重存储和名称图 ------------------------
#此选项需要三重存储（我们使用 GraphDB）
#对于 GraphDB，Krystal 需要事先创建一个存储库
#用于将输出数据存储到三重存储的选项（真/假）

live-store: true

#Triple Store type (e.g., graphdb, virtuoso)
#三重存储类型（例如 graphdb、virtuoso）

triple-store: graphdb

#Endpoint for storing rdf output to the triple Store
#For GraphDB, the sparql-endpoint can be access via http://localhost:7200/repositories/<repository-name>
#将 rdf 输出存储到三元组存储的端点
#对于 GraphDB，可以通过 http://localhost:7200/repositories/<repository-name> 访问 sparql 端点

sparql-endpoint: http://localhost:7200/repositories/Krystal

#Namegraph of the RDF graph on the triplestore (the output filename will be generated based on this namegraph)
#三重存储上的 RDF 图的名称图（输出文件名将根据此名称图生成）
namegraph: http://w3id.org/sepses/graph/cadets

#----------------------------- SYSTEM SETTING -------------------------------------------
#Jena TDB directory, this directory is required for storing jena TDB temporary files
#Jena TDB目录，该目录用于存放jena TDB临时文件
tdb-dir: experiment/tdb

#Directory for Krystal Ontology 
#Krystal Ontology 目录
ontology: experiment/ontology/log-ontology.ttl

#OS platform of the log sources, (e.g. ubuntu14 for cadets, trace ; freebsd for theia ; windows for fivedirections)
#日志源的 OS 平台，（例如 cadets、trace 的 OS 平台为 ubuntu14；theia 的 OS 平台为 freebsd；fivedirections 的 OS 平台为 windows）
os-platform: ubuntu14

#----------------------------- THREAT DETECTION TECHNIQUES -------------------------------
#List of possible threat detection techniques, set to "true" to apply otherwise set to "false"
#----------------------------- 威胁检测技术 -------------------------------
#可能的威胁检测技术列表，设置为“true”表示应用，否则设置为“false”
tag-propagation: true

#Setting tag-attenuation to true requires tag-propagation also to be true 
#将 tag-attenuation 设置为 true 需要 tag-propagation 也为 true
tag-attenuation: true
ab: 0.2 #attenuation value for benign 良性衰减值
ae: 0.1 #attenuation value for suspect  嫌疑人的衰减值

#将 tag-decay 设置为 true 需要 tag-propagation 也为 true
#Setting tag-decay to true requires tag-propagation also to be true 
tag-decay: true
period: 0.25 #decay half live (second)
tb: 0.75 #quiescent tag values for benign
te: 0.45 #aquiescent tag values for suspect

#将 policy-based-rule 设置为 true 需要 tag-propagation 和 tag-attenuation-decay 也为 true
#Setting policy-based-rule to true requires tag-propagation and tag-attenuation-decay also to be true 
policy-based-rule: true

#签名库检测，目前仅支持Sigma Rules的规则检测
#Signature base detection, currently only supports rule detection from Sigma Rules 
signature-based-rule: true 

#Sigma Linux 规则目录
#Sigma rule directory for linux 
rule-dir : experiment/rule/

#Sigma 规则目录（适用于 Windows）
#Sigma rule directory for windows
rule-dir-win : experiment/rule_win/ 

#----------------------------- CONFIDENTIAL DIRECTORY -------------------------------
#List of any confidential directory on the targetted hosts / logsources 
#These will be used as initialization for confidentiality scores in the tag-propagation technique during provenance graph building
#----------------------------- 机密目录 -------------------------------
#目标主机/日志源上的任何机密目录的列表
#这些将在来源图构建期间用作标签传播技术中机密性分数的初始化
confidential-dir:
 - /etc/passwd
 - /var/log
 - /etc/shadow
 - /documents/

 #----------------------------- AUDIT EVENTS-----------------------------------------
#List of any events from audit data that need to be included in the provenance graph building
#Event filter for log processing (events with # will be ignored)
#需要包含在来源图构建中的审计数据中的任何事件的列表
#用于日志处理的事件过滤器（带有#的事件将被忽略）
field-filter:
 #- EVENT_FORK
 - EVENT_EXIT
 - EVENT_MPROTECT
 - EVENT_LOGIN
 #- EVENT_CLONE
 #- EVENT_LOADLIBRARY
 #- EVENT_EXECUTE
....
```

### Running the Application:

To run the compiled project: 

```bash
$ java -jar ./target/Krystal-1.1.0-jar-with-dependencies.jar
```
The log processing will take some time depending on the size of the input data. After processing the input data, several output files will be produced, such as the dependency (provenance) graphs (in RDF/.ttl files), the alert data (in RDF-star/.ttl), and the compressed version of the RDF graph (in .hdt). We provided several example RDF output files (in RDF and .HDT) under the directory [experiment/output](https://github.com/sepses/Krystal/tree/main/experiment/output). 

日志处理将需要一些时间，具体取决于输入数据的大小。处理输入数据后，将生成多个输出文件，例如依赖关系（来源）图（在 RDF/.ttl 文件中）、警报数据（在 RDF-star/.ttl 中）和 RDF 图的压缩版本（在 .hdt 中）。我们在目录 [experiment/output](https://github.com/sepses/Krystal/tree/main/experiment/output) 下提供了几个示例 RDF 输出文件（在 RDF 和 .HDT 中）。

## Running Example
See the example process below:

```bash
$ java -jar java -jar ./target/Krystal-1.1.0-jar-with-dependencies.jar
    __ __                 __        __   ______                                             __
   / //_/_______  _______/ /_____ _/ /  / ____/________ _____ ___  ___ _      ______  _____/ /__
  / ,<  / ___/ / / / ___/ __/ __ `/ /  / /_  / ___/ __ `/ __ `__ \/ _ \ | /| / / __ \/ ___/ //_/
 / /| |/ /  / /_/ (__  ) /_/ /_/ / /  / __/ / /  / /_/ / / / / / /  __/ |/ |/ / /_/ / /  / ,<
/_/ |_/_/   \__, /____/\__/\__,_/_/  /_/   /_/   \__,_/_/ /_/ /_/\___/|__/|__/\____/_/  /_/|_|
           /____/


Start running ubuntu14 parser...
Threat detection techniques:
- Tag-Propagation: true
- Tag-Attenuation: true
- Tag-Decay: true
- Policy-Rule: true
- Signature-Rule: true
processing file: cadets100000.json
reading from line : 1
parsing 1 of 100000 finished in 10322
Total Time: 10705805600
the rest is less than 100000 which is 3
Total Time: 10706591400
finish processing file: experiment/input/cadets/cadets100000.json
generate alert from sigma rule experiment/rule/
number of events :94050
Statictics:
http://w3id.org/sepses/resource/rule/corrupt-file-rule : 6
http://w3id.org/sepses/resource/rule/change-permission-rule : 20
http://w3id.org/sepses/resource/sigma/sigma-444ade84-c362-4260-b1f3-e45e20e1a905 : 1
Save model to rdf file...experiment/output/cadets_output.ttl Done!
Save model to rdf file...experiment/output/cadets_alert_output.ttl Done!
Save model rdf to hdt....experiment/output/experiment/output/cadets_output.hdt Done!
Store experiment/ontology/log-ontology.ttl to [graphdb] via http://localhost:7200/repositories/Krystal using namegraph http://w3id.org/sepses/graph/cadets ... Done!
Store experiment/output/cadets_output.ttl to [graphdb] via http://localhost:7200/repositories/Krystal using namegraph http://w3id.org/sepses/graph/cadets ... Done!
Store experiment/output/cadets_alert_output.ttl to [graphdb] via http://localhost:7200/repositories/Krystal using namegraph http://w3id.org/sepses/graph/cadets ... Done!
```
## Analyzing / Querying the Graph
The resulting output data (the RDF data) can already be queried for analysis e.g. for root cause analysis, attack graph reconstruction (via graph query or forward chaining technique), etc. The directory [experiment/query](https://github.com/sepses/Krystal/tree/main/experiment/query) contains several example queries that can be used for analysis. Figure 2 shows an example output of attack graph construction using *backward-forward* chaining technique. 

生成的输出数据（RDF 数据）已经可以查询进行分析，例如进行根本原因分析、攻击图重建（通过图查询或前向链接技术）等。目录 [experiment/query](https://github.com/sepses/Krystal/tree/main/experiment/query) 包含几个可用于分析的示例查询。图 2 显示了使用 *后向-前向* 链接技术构建攻击图的示例输出。

![ ](https://raw.githubusercontent.com/kabulkurniawan/Krystal/main/cadets_03.png)<p align="center"> **Figure 2** Attack Graph Construction Output Example.

**Nginx backdoor w/ Drakon in-memory** (FreeBSD/Cadets). *The attack begins with a vulnerable Nginx installed on a FreeBSD host that gets exploited by an attacker. The attacker sends a malformed HTTP request that results in downloading several malicious files on the local system. One of the files i.e. /tmp/pEja72mA then gets executed, which spawns a process pEja72mA. This process reads sensitive information/etc/passwd) and connects remotely via C&C to the attacker console*.

**Nginx 后门，带有 Drakon 内存** (FreeBSD/Cadets)。*攻击始于安装在 FreeBSD 主机上的易受攻击的 Nginx，攻击者会利用该 Nginx。攻击者发送格式错误的 HTTP 请求，导致在本地系统上下载多个恶意文件。然后执行其中一个文件（即 /tmp/pEja72mA），从而生成进程 pEja72mA。此进程读取敏感信息（/etc/passwd）并通过 C&C 远程连接到攻击者控制台*。

## Cite
```bash
@article{kurniawan_krystal_2022,
author = {Kabul Kurniawan and Andreas Ekelhart and Elmar Kiesling and Gerald Quirchmayr and A Min Tjoa},
title = {KRYSTAL: Knowledge graph-based framework for tactical attack discovery in audit data},
journal = {Computers & Security},
volume = {121},
pages = {102828},
year = {2022},
issn = {0167-4048},
doi = {https://doi.org/10.1016/j.cose.2022.102828},
url = {https://www.sciencedirect.com/science/article/pii/S016740482200222X}
}
```

## License

The Krystal Framework is written by [Kabul Kurniawan](https://kabulkurniawan.github.io/) and released under the [MIT license](http://opensource.org/licenses/MIT).

