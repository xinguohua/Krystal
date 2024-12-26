package sepses.krystal.parser;

import java.io.IOException;
import java.io.Reader;
import java.io.StringReader;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

import com.fasterxml.jackson.databind.JsonNode;
import org.apache.jena.rdf.model.Model;
import com.jsoniter.JsonIterator;
import com.jsoniter.any.Any;

import sepses.krystal.AlertRule;
import sepses.krystal.PropagationRule;

public class LogParserUbuntu14 {
    public String eventType;
    public Any eventNode;
    public Any networkNode;
    public Any subjectNode;
    public Any userNode;
    public Any hostNode;
    public Any datumNode;
    public String objectAbsPath;

    public String exec;
    public String hostId;
    public String userId;

    public String timestamp;
    public String subjectId;
    public String objectUUID;
    public String networkId;
    public String netAddress;

    public String cmdline;

    public LogParserUbuntu14(String line) {
        Any jsonNode = JsonIterator.deserialize(line);
        datumNode = jsonNode.get("datum");

    }

    public String parseJSONtoRDF(Model jsonModel, Model alertModel, ArrayList<String> fieldfilter, ArrayList<String> confidentialdir,
                                 HashMap<String, String> uuIndex, Set<String> processSet, Set<String> fileSet, Set<String> networkSet,
                                 HashMap<String, String> networkId2Adress, HashMap<String, String> subject2Process, Set<String> lastEvent, String lastAccess,
                                 HashMap<String, String> subject2User, HashMap<String, Long> subject2Time, String propagation,
                                 String attenuation, double ab, double ae, String decayrule, double period, double Tb, double Te, String policyrule, String signaturerule, AtomicInteger counter, HashMap<String, String> subject2Cmd) throws IOException {
        //filter is the line is an event or not
        eventNode = datumNode.get("com.bbn.tc.schema.avro.cdm18.Event");
        if (eventNode.toBoolean()) {
            counter.incrementAndGet();
            eventType = eventNode.toString();
            if (filterLine(eventType, fieldfilter)) {
                return lastAccess;
            }

            String mapper = "";
            LogMapper lm = new LogMapper();
            subjectId = shortenUUID(eventNode.get("subject").get("com.bbn.tc.schema.avro.cdm18.UUID").toString(), uuIndex);
            objectUUID = shortenUUID(eventNode.get("predicateObject").get("com.bbn.tc.schema.avro.cdm18.UUID").toString(), uuIndex);
            objectAbsPath = cleanLine(eventNode.get("predicateObjectPath").get("string").toString());

            exec = getSubjectCmd(subjectId, subject2Cmd);
            hostId = eventNode.get("hostId").toString();
            userId = getUserId(subjectId, subject2User);

            long ts = eventNode.get("timestampNanos").toLong();
            String timestamp = eventNode.get("timestampNanos").toString();
            long initTime = getSubjectTime(subjectId, subject2Time);

            PropagationRule prop = new PropagationRule();

            //time initialization for each process
            if (initTime == 0) {
                putNewSubjectTime(subjectId, ts, subject2Time);
                initTime = ts;
            }
            prop.putProcessTime(jsonModel, subjectId, exec, initTime);


            String processMap = "";
            String fileMap = "";
            String prevProcess = "";
            String networkMap = "";

            if (!Objects.equals(decayrule, "false")) {
                if (ts != 0 && !eventType.contains("EVENT_FORK")) {
                    prop.decayIndividualProcess(jsonModel, subjectId + "#" + exec, ts, period, Tb, Te);
                }
            }

            //is file new
            if (isEntityNew(objectAbsPath, fileSet)) {
                //is file confidential
                if (isConfidentialFile(objectAbsPath, confidentialdir)) {
                    fileMap = lm.initialConfFileTagMap(objectAbsPath);
                } else {
                    fileMap = lm.initialFileTagMap(objectAbsPath);
                }
            }

            //is process new
            if (isEntityNew(subjectId + "#" + exec, processSet)) {
                //is it forked by another previous process?
                prevProcess = getPreviousForkProcess(subjectId, subject2Process);
                //if yes create fork Event
                if (!prevProcess.isEmpty()) {
                    if (!eventType.contains("EVENT_EXECUTE")) {
                        forkEvent(lm, prevProcess, subjectId + "#" + exec, timestamp, jsonModel);
                    }
                } else {
                    //tag new process
                    processMap = lm.initialProcessTagMap(subjectId + "#" + exec);
                }
            }

            if (eventType.contains("EVENT_WRITE")) {
                if (!Objects.equals(objectAbsPath, "") && !objectAbsPath.contains("<unknown>")) {
                    String curWrite = subjectId + exec + objectAbsPath + "write";
                    if (!lastAccess.contains(curWrite)) {
                        mapper = lm.writeMap(subjectId, exec, objectAbsPath, hostId, userId, timestamp) + fileMap + processMap;

                        storeEntity(objectAbsPath, fileSet);
                        storeEntity(subjectId + "#" + exec, processSet);

                        Reader targetReader = new StringReader(mapper);
                        jsonModel.read(targetReader, null, "N-TRIPLE");
                        if (!Objects.equals(policyrule, "false")) {
                            AlertRule alert = new AlertRule();
                            alert.corruptFileAlert(jsonModel, alertModel, subjectId + "#" + exec, objectAbsPath, timestamp);
                        }

                        if (!Objects.equals(attenuation, "false")) {
                            prop.writeTagWithAttenuation(jsonModel, subjectId, exec, objectAbsPath, ab, ae, propagation);
                        } else {
                            prop.writeTag(jsonModel, subjectId, exec, objectAbsPath, propagation);
                        }
                        lastAccess = curWrite;
                    }
                }
            } else if (eventType.contains("EVENT_READ")) {
                //check last read to reduce unnecessary duplicate event processing
                String curRead = subjectId + exec + objectAbsPath + "read";
                if (!Objects.equals(objectAbsPath, "") && !objectAbsPath.contains("<unknown>")) {
                    if (!lastAccess.contains(curRead)) {
                        mapper = lm.readMap(subjectId, exec, objectAbsPath, hostId, userId, timestamp) + fileMap + processMap;

                        storeEntity(objectAbsPath, fileSet);
                        storeEntity(subjectId + "#" + exec, processSet);

                        Reader targetReader = new StringReader(mapper);
                        jsonModel.read(targetReader, null, "N-TRIPLE");

                        prop.readTag(jsonModel, subjectId, exec, objectAbsPath, propagation);
                        lastAccess = curRead;
                    }
                }
            } else if (eventType.contains("EVENT_EXECUTE")) {

                cmdline = eventNode.get("properties").get("map").get("cmdLine").toString();
                cmdline = cleanCmd(cmdline);

                String executedProcess = "";

                if (cmdline.contains(" ")) {
                    String newproc = cmdline.substring(0, cmdline.indexOf(" "));
                    String[] nnewproc = newproc.split("/"); //incase there is full path e.g. "/tmp/vUgefal"
                    if (nnewproc.length > 1) {
                        executedProcess = nnewproc[nnewproc.length - 1];
                    } else {
                        executedProcess = newproc;
                    }
                } else {
                    executedProcess = cmdline;
                }

                if (!executedProcess.isEmpty()) {
                    if (prevProcess.isEmpty()) {
                        putNewForkObject(subjectId + "#" + exec, subjectId, subject2Process);
                        prevProcess = getPreviousForkProcess(subjectId, subject2Process);
                    }

                    Reader targetReader = new StringReader(processMap);
                    jsonModel.read(targetReader, null, "N-TRIPLE");

                    forkEvent(lm, prevProcess, subjectId + "#" + executedProcess, timestamp, jsonModel);
                    mapper = lm.executeMap(subjectId, executedProcess, objectAbsPath, cmdline, hostId, userId, timestamp) + fileMap;

                    storeEntity(objectAbsPath, fileSet);
                    storeEntity(subjectId + "#" + exec, processSet);
                    storeEntity(subjectId + "#" + executedProcess, processSet);

                    Reader targetReader2 = new StringReader(mapper);
                    jsonModel.read(targetReader2, null, "N-TRIPLE");

                    if (initTime != 0) {
                        prop.putProcessTime(jsonModel, subjectId, executedProcess, initTime);
                    }
                    if (!Objects.equals(decayrule, "false")) {
                        prop.decayIndividualProcess(jsonModel, subjectId + "#" + executedProcess, ts, period, Tb, Te);
                    }

                    if (!Objects.equals(policyrule, "false")) {
                        AlertRule alert = new AlertRule();
                        alert.execAlert(jsonModel, alertModel, subjectId + "#" + executedProcess, objectAbsPath, timestamp);
                    }
                    prop.execTag(jsonModel, subjectId, executedProcess, objectAbsPath, propagation);
                }
            } else if (eventType.contains("EVENT_FORK")) {
                putNewForkObject(subjectId + "#" + exec, objectUUID, subject2Process);
                storeEntity(subjectId + "#" + exec, processSet);
                Reader targetReader = new StringReader(processMap);
                jsonModel.read(targetReader, null, "N-TRIPLE");
            } else if (eventType.contains("EVENT_MODIFY_FILE_ATTRIBUTES")) {
                String curCh = subjectId + exec + objectAbsPath + "change";
                if (!lastAccess.contains(curCh)) {
                    mapper = lm.changePerm(subjectId, exec, objectAbsPath, hostId, userId, timestamp);

                    Reader targetReader = new StringReader(mapper);
                    jsonModel.read(targetReader, null, "N-TRIPLE");

                    if (!Objects.equals(policyrule, "false")) {
                        AlertRule alert = new AlertRule();
                        alert.changePermAlert(jsonModel, alertModel, subjectId + "#" + exec, objectAbsPath, timestamp);
                    }
                    lastAccess = curCh;
                }
            } else if (eventType.contains("EVENT_SENDTO") || eventType.contains("EVENT_SENDMSG")) {
                String ipAddress = getIpAddress(objectUUID, networkId2Adress);

                if (!ipAddress.isEmpty()) {
                    if (isEntityNew(ipAddress, networkSet)) {
                        networkMap = lm.initialNetworkTagMap(ipAddress);
                    }
                    String curSend = subjectId + exec + ipAddress + "send";
                    if (!lastAccess.contains(curSend)) {

                        mapper = lm.sendMap(subjectId, exec, ipAddress, hostId, userId, timestamp) + networkMap + processMap;

                        storeEntity(ipAddress, networkSet);
                        storeEntity(subjectId + "#" + exec, processSet);

                        Reader targetReader = new StringReader(mapper);
                        jsonModel.read(targetReader, null, "N-TRIPLE");

                        if (!Objects.equals(policyrule, "false")) {
                            AlertRule alert = new AlertRule();
                            alert.dataLeakAlert(jsonModel, alertModel, subjectId + "#" + exec, ipAddress, timestamp);
                        }
                        prop.sendTag(jsonModel, subjectId, exec, ipAddress, propagation);
                        lastAccess = curSend;
                    }
                }
            } else if (eventType.contains("EVENT_RECVFROM") || eventType.contains("EVENT_RECVMSG")) {
                String ipAddress = getIpAddress(objectUUID, networkId2Adress);
                if (!ipAddress.isEmpty()) {
                    if (isEntityNew(ipAddress, networkSet)) {
                        networkMap = lm.initialNetworkTagMap(ipAddress);
                    }
                    mapper = lm.receiveMap(subjectId, exec, ipAddress, hostId, userId, timestamp) + networkMap + processMap;

                    storeEntity(ipAddress, networkSet);
                    storeEntity(subjectId + "#" + exec, processSet);

                    Reader targetReader = new StringReader(mapper);
                    jsonModel.read(targetReader, null, "N-TRIPLE");

                    //every connection is evil, hence update the new time to avoid decay
                    putNewSubjectTime(subjectId, ts, subject2Time);

                    if (!Objects.equals(policyrule, "false")) {
                        AlertRule alert = new AlertRule();
                        alert.reconnaissanceAlert(jsonModel, alertModel, subjectId + "#" + exec, ipAddress, timestamp);
                    }
                    prop.receiveTag(jsonModel, subjectId, exec, ipAddress, propagation);
                }
            }

        } else if (datumNode.get("com.bbn.tc.schema.avro.cdm18.NetFlowObject").toBoolean()) {
            networkNode = datumNode.get("com.bbn.tc.schema.avro.cdm18.NetFlowObject");
            networkId = shortenUUID(networkNode.get("uuid").toString(), uuIndex);
            String ip = networkNode.get("remoteAddress").toString();
            String port = networkNode.get("remotePort").toString();
            netAddress = ip + ":" + port;
            putNewNetworkObject(networkId, netAddress, networkId2Adress);
            String mapper = "";
            LogMapper lm = new LogMapper();
            mapper = lm.networkMap(netAddress, ip, port);
            Reader targetReader = new StringReader(mapper);
            jsonModel.read(targetReader, null, "N-TRIPLE");
        } else if (datumNode.get("com.bbn.tc.schema.avro.cdm18.Subject").toBoolean()) {
            subjectNode = datumNode.get("com.bbn.tc.schema.avro.cdm18.Subject");
            subjectId = shortenUUID(subjectNode.get("uuid").toString(), uuIndex);
            String userId = shortenUUID(subjectNode.get("localPrincipal").toString(), uuIndex);
            putNewUserObject(subjectId, userId, subject2User);
            long time = subjectNode.get("startTimestampNanos").toLong();
            if (time != 0) {
                putNewSubjectTime(subjectId, time, subject2Time);
            }
            exec = subjectNode.get("properties").get("map").get("name").toString();
            putNewSubjectCmd(subjectId, exec, subject2Cmd);
        } else if (datumNode.get("com.bbn.tc.schema.avro.cdm18.Principal").toBoolean()) {
            String mapper = "";
            LogMapper lm = new LogMapper();
            userNode = datumNode.get("com.bbn.tc.schema.avro.cdm18.Principal");
            userId = shortenUUID(userNode.get("uuid").toString(), uuIndex);
            String userType = getUserType(userNode.get("userId").toInt());
            String userName = userNode.get("username").get("string").toString();
            mapper = lm.userMap(userId, userType, userName);
            Reader targetReader = new StringReader(mapper);
            jsonModel.read(targetReader, null, "N-TRIPLE");
        } else if (datumNode.get("com.bbn.tc.schema.avro.cdm18.Host").toBoolean()) {
            String mapper = "";
            LogMapper lm = new LogMapper();
            hostNode = datumNode.get("com.bbn.tc.schema.avro.cdm18.Host");
            hostId = hostNode.get("uuid").toString();
            String hostName = hostNode.get("hostName").toString();
            String hostOS = hostNode.get("osDetails").toString();
            String hostIP = hostNode.get("interfaces").get(1).get("ipAddresses").get(1).toString();
            mapper = lm.hostMap(hostId, hostName, hostOS, hostIP);
            Reader targetReader = new StringReader(mapper);
            jsonModel.read(targetReader, null, "N-TRIPLE");
        }
        return lastAccess;
    }


    private void forkEvent(LogMapper lm, String prevProcess, String process, String ts, Model jsonModel) {
        if (!prevProcess.equals(process)) {
            String forkMap = lm.forkMap(prevProcess, process, ts);
            Reader targetReader = new StringReader(forkMap);
            jsonModel.read(targetReader, null, "N-TRIPLE");
            PropagationRule prop = new PropagationRule();
            prop.forkTag(jsonModel, prevProcess, process);
        }
    }

    private static String shortenUUID(String uuid, HashMap<String, String> uuid2Index) {
        String id = "";
        if (!uuid.isEmpty()) {
            if (uuid2Index.containsKey(uuid)) {
                id = uuid2Index.get(uuid);
            } else {
                int lastId = uuid2Index.size() + 1;
                String currId = Integer.toString(lastId);
                id = currId;
                uuid2Index.put(uuid, currId);
            }
        }
        return id;
    }

    private static boolean isEntityNew(String entity, Set<String> store) {
        //process
        boolean entityNew = false;
        if (!entity.isEmpty()) {
            if (!store.contains(entity)) {
                entityNew = true;
            }
        }
        return entityNew;
    }

    private static void storeEntity(String entity, Set<String> store) {
        if (!entity.isEmpty()) {
            store.add(entity);
        }
    }


    private static String getIpAddress(String netWorkId, HashMap<String, String> networkId2Adress) {
        //process
        String ipAddress = "";
        if (!netWorkId.isEmpty()) {
            if (networkId2Adress.containsKey(netWorkId)) {
                ipAddress = networkId2Adress.get(netWorkId);
            }
        }
        return ipAddress;
    }

    private static void putNewNetworkObject(String netObject, String netAddress, HashMap<String, String> NetworkObject) {
        //process
        if (!netObject.isEmpty() && !netAddress.isEmpty()) {
            if (!NetworkObject.containsKey(netObject)) {
                NetworkObject.put(netObject, netAddress);
            }
        }
    }

    private static String getUserId(String subject, HashMap<String, String> UserObject) {
        //process
        String userId = "";
        if (!subject.isEmpty()) {
            if (UserObject.containsKey(subject)) {
                userId = UserObject.get(subject);
            }
        }

        return userId;
    }

    private static void putNewUserObject(String subject, String userId, HashMap<String, String> UserObject) {
        //process
        if (!subject.isEmpty() && !userId.isEmpty()) {
            if (!UserObject.containsKey(subject)) {
                UserObject.put(subject, userId);
            }
        }
    }

    private static void putNewForkObject(String process, String subject, HashMap<String, String> subject2Process) {
        //process
        if (!process.isEmpty() && !subject.isEmpty()) {
            if (!subject2Process.containsKey(subject)) {
                subject2Process.put(subject, process);
            } else {
                //update
                subject2Process.remove(subject);
                subject2Process.put(subject, process);
            }
        }

    }

    private static String getPreviousForkProcess(String subject, HashMap<String, String> subject2Process) {
        //process
        String prevProcess = "";
        if (!subject.isEmpty()) {
            if (subject2Process.containsKey(subject)) {
                prevProcess = subject2Process.get(subject);
            }
        }
        return prevProcess;
    }


    private static Boolean filterLine(String eventType, ArrayList<String> fieldfilter) {
        boolean result = false;
        for (String s : fieldfilter) {
            if (eventType.contains(s)) {
                result = true;
                break;
            }
        }
        return result;
    }

    private static boolean isConfidentialFile(String file, ArrayList<String> confidentialdir) {
        boolean fileexist = false;
        if (!file.isEmpty()) {
            for (String s : confidentialdir) {
                if (file.contains(s)) {
                    fileexist = true;
                    break;
                }
            }
        }

        return fileexist;
    }

    private static String cleanLine(String line) {
        line = line.replaceAll("[#{}%\\]\\[\\s\\n:$=()]", "");
        return line;
    }

    private static String cleanCmd(String line) {
        line = line.replaceAll("[\\n\\t]", "");

        return line;
    }

    private String getUserType(Integer userType) {
        if (userType == 0) {
            return "RootUser";
        } else if (userType >= 1 && userType <= 1000) {
            return "LocalUser";
        } else {
            return "SystemUser";
        }

    }


    private static void putNewSubjectTime(String subject, long time, HashMap<String, Long> subject2Time) {
        //process
        if (!subject.isEmpty()) {
            if (!subject2Time.containsKey(subject)) {
                subject2Time.put(subject, time);
            } else {
                subject2Time.remove(subject);
                subject2Time.put(subject, time);
            }
        }
    }

    private static long getSubjectTime(String subject, HashMap<String, Long> subject2Time) {
        //process
        long time = 0;
        if (!subject.isEmpty()) {
            if (subject2Time.containsKey(subject)) {
                time = subject2Time.get(subject);
            }
        }
        return time;
    }

    private static void updateCounter(ArrayList<Integer> counter) {
        int lastCounter = counter.get(0);
        counter.remove(0);
        counter.add(lastCounter + 1);
    }

    private static void putNewSubjectCmd(String subject, String cmdLine, HashMap<String, String> SubjectCmd) {
        //process
        if (!subject.isEmpty() && !cmdLine.isEmpty()) {
            if (!SubjectCmd.containsKey(subject)) {
                SubjectCmd.put(subject, cmdLine);
            }
        }
    }

    private static String getSubjectCmd(String subject, HashMap<String, String> subjectCmd) {
        //process
        String exec = "";
        if (!subject.isEmpty()) {
            if (subjectCmd.containsKey(subject)) {
                exec = subjectCmd.get(subject);
            }
        }
        return exec;
    }
}
