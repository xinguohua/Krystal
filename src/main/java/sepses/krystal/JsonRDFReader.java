package sepses.krystal;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.jena.atlas.lib.Alarm;
import org.apache.jena.query.Dataset;
import org.apache.jena.rdf.model.InfModel;
import org.apache.jena.rdf.model.Model;
import org.apache.jena.rdf.model.ModelFactory;
import org.apache.jena.reasoner.Reasoner;
import org.apache.jena.reasoner.ReasonerRegistry;
import org.apache.jena.riot.RDFDataMgr;
import org.apache.jena.tdb.TDBFactory;

import sepses.krystal.helper.Utility;
import sepses.krystal.parser.*;

public class JsonRDFReader {

    static long startTime;


    public static void readJson(String filefolder, String l, String se, String ng, String sl, String outputdir, String triplestore, String backupfile, ArrayList<String> fieldfilter, String livestore, ArrayList<String> confidentialdir, String tdbdir, String ontology, String ruledir, String os, String propagation, String attenuation, double ab, double ae, String decayrule, double period, double tb, double te, String policyrule, String signaturerule) throws Exception {

        startTime = System.nanoTime();
        int lineNumber = 1; // 1 here means the minimum line to be extracted
        if (l != null) {
            lineNumber = Integer.parseInt(l);
        }
        String sparqlEp = se;
        String nameGraph = ng;
        int startingLine = 1; // 1 means start from the beginning
        if (sl != null) {
            startingLine = Integer.parseInt(sl);
        }

        // create in one json object
        Integer countLine = 0;
        Integer templ = 0;
        int group = 0;

        //provenance Model store in TDB
        Dataset d = TDBFactory.createDataset(tdbdir);
        Model jsonModel = d.getDefaultModel();
        long time1 = System.currentTimeMillis();


        //alert model store in jena model
        Model alertModel = ModelFactory.createDefaultModel();


        Set<String> Process = new HashSet<>();
        Set<String> File = new HashSet<>();
        Set<String> Network = new HashSet<>();
        Set<String> Registry = new HashSet<>();
        Set<String> lastEvent = new HashSet<>();

        HashMap<String, String> uuIndex = new HashMap<>();
        HashMap<String, String> NetworkObject = new HashMap<>();
        HashMap<String, String> FileObject = new HashMap<>();
        HashMap<String, String> ForkObject = new HashMap<>();
        HashMap<String, String> UserObject = new HashMap<>();
        HashMap<String, String> SubjectCmd = new HashMap<>();
        HashMap<String, Long> SubjectTime = new HashMap<>();
        HashMap<String, String> CloneObject = new HashMap<>();
        HashMap<String, String> RegistryObject = new HashMap<>();
        ArrayList<Integer> counter = new ArrayList<>();
        counter.add(0);
        AtomicInteger counter1 = new AtomicInteger();
        counter1.set(0);
        String lastAccess = "";


        File folder = new File(filefolder);

        ArrayList<String> listFiles = Utility.listFilesForFolder(folder);
        Collections.sort(listFiles);

        if (listFiles.isEmpty()) {
            System.out.print("folder is empty!");
            System.exit(0);
        }
        for (String file : listFiles) {
            System.out.println("processing file: " + file);
            String filename = filefolder + file;

            InputStream jf = Files.newInputStream(Paths.get(filename));
            BufferedReader in = new BufferedReader(new InputStreamReader(jf));

            while (in.ready()) {
                String line = in.readLine();
                if (countLine.equals(startingLine)) {
                    System.out.println("reading from line : " + startingLine);
                    group = ((int) Math.ceil((double) (startingLine - 1) / lineNumber));
                }
                if (countLine >= startingLine) {
                    //line = cleanLine(line); // sometimes the data should be cleaned first
                    //skip strange character inside line
                    try {
                        switch (os) {
                            case "windows": {
                                int lastChar = line.length() - 1;
                                if (line.substring(lastChar, line.length()).equals(",")) {
                                    line = line.substring(0, line.length() - 1);
                                }
                                LogParserWin lp = new LogParserWin(line); //fivedirection

                                lastAccess = lp.parseJSONtoRDF(jsonModel, alertModel, fieldfilter, confidentialdir, uuIndex, Process, File, Network, NetworkObject, ForkObject, lastEvent, lastAccess, UserObject, Registry, RegistryObject, SubjectCmd, file, SubjectTime, propagation, attenuation, ab, ae, decayrule, period, tb, te, policyrule, signaturerule, counter);
                                break;
                            }
                            case "ubuntu12": {
                                LogParserUbuntu12 lp = new LogParserUbuntu12(line); //ubuntu

                                lastAccess = lp.parseJSONtoRDF(jsonModel, alertModel, fieldfilter, confidentialdir, uuIndex, Process, File, Network, NetworkObject, ForkObject, lastEvent, lastAccess, UserObject, FileObject, SubjectCmd, file, CloneObject, propagation, attenuation, ab, ae, decayrule, period, tb, te, policyrule, signaturerule, counter);
                                break;
                            }
                            case "ubuntu14": {
//                                LogParserUbuntu14 lp = new LogParserUbuntu14(line); //freebsd
//                                lastAccess = lp.parseJSONtoRDFWithAlert(jsonModel, alertModel, fieldfilter, confidentialdir, uuIndex, Process, File, Network, NetworkObject, ForkObject, lastEvent, lastAccess, UserObject, SubjectTime, propagation, attenuation, ab, ae, decayrule, period, tb, te, policyrule, signaturerule, counter1, SubjectCmd);
                                LogParserUbuntuNew14 lp = new LogParserUbuntuNew14(line); //freebsd
                                lastAccess = lp.parseJSONtoRDF(jsonModel, fieldfilter, uuIndex, Process, File, Network, NetworkObject, ForkObject, lastAccess, UserObject, counter1, SubjectCmd);
                                break;
                            }
                            default: {
                                LogParserFreeBSD lp = new LogParserFreeBSD(line); //freebsd

                                lastAccess = lp.parseJSONtoRDF(jsonModel, alertModel, fieldfilter, confidentialdir, uuIndex, Process, File, Network, NetworkObject, ForkObject, lastEvent, lastAccess, UserObject, SubjectTime, propagation, attenuation, ab, ae, decayrule, period, tb, te, policyrule, signaturerule, counter);
                                break;
                            }
                        }

                    } catch (Exception e) {
                        System.out.print("strange character skipped => ");
                        System.out.println(line);
                    }

                    templ++;

                    if (templ.equals(lineNumber)) {
                        group++;
                        System.out.println("parsing " + group + " of " + lineNumber + " finished in " + (System.currentTimeMillis() - time1));
                        long endTime = System.nanoTime();
                        long totalTime = endTime - startTime;
                        System.out.println("Total Time: " + totalTime);
                        templ = 0;
                    }
                }
                countLine++;
            }
            // check the rest
            in.close();
            if (templ != 0) {
                System.out.println("the rest is less than " + lineNumber + " which is " + templ);
                long endTime = System.nanoTime();
                long totalTime = endTime - startTime;
                System.out.println("Total Time: " + totalTime);
                templ = 0;
            }
            //end of a file
            System.out.println("finish processing file: " + filename);
        }
        //end of folder
        //  Create the Reasoner
        Reasoner reasoner = ReasonerRegistry.getOWLMicroReasoner();
        //  Bind the Ontology Schema
        reasoner = reasoner.bindSchema(RDFDataMgr.loadModel(ontology));
        //  Create an Inference Model
        InfModel infModel = ModelFactory.createInfModel(reasoner, jsonModel);

        System.out.println("number of events :" + counter.get(0));
        if (!Objects.equals(backupfile, "false")) {
            String rdfFile = Utility.saveToRDF(infModel, outputdir, nameGraph);
            Utility.exportHDT(rdfFile, outputdir, nameGraph);
            if (!Objects.equals(livestore, "false")) {
                // Store the inferred RDF data
                Utility.storeFileInRepo(triplestore, rdfFile, sparqlEp, nameGraph, "dba", "dba");
            }
        }

        // alert logic
//        if (!Objects.equals(signaturerule, "false")) {
//            //detect alert from rule dir (i.e. sigma rule)
//            AlertRule.generateAlertFromRuleDir(infModel, alertModel, ruledir);
//        }
//        Statistic.countAlarm(alertModel);
//        if (!Objects.equals(backupfile, "false")) {
//            //   alert is not included in HDT, as it doesn't support RDF-star yet
//            String alertFile = Utility.saveToRDF(alertModel, outputdir, nameGraph + "_alert");
//            if (!Objects.equals(livestore, "false")) {
//                // Store the ontology file
//                Utility.storeFileInRepo(triplestore, ontology, sparqlEp, nameGraph, "dba", "dba");
//                // Store the generated alert file
//                Utility.storeFileInRepo(triplestore, alertFile, sparqlEp, nameGraph, "dba", "dba");
//            }
//        }
    }
}
