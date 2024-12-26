package sepses.krystal;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Objects;

import org.apache.jena.query.QueryExecution;
import org.apache.jena.query.QueryExecutionFactory;
import org.apache.jena.query.QuerySolution;
import org.apache.jena.query.ResultSet;
import org.apache.jena.rdf.model.Model;
import org.apache.jena.rdf.model.ModelFactory;
import org.apache.jena.rdf.model.Property;
import org.apache.jena.rdf.model.RDFNode;
import org.apache.jena.rdf.model.Resource;
import org.apache.jena.rdf.model.Statement;
import org.apache.jena.rdf.model.StmtIterator;


public class PropagationRule {
    public String prefRule;
    public String prefix;
    public String process;
    public String file;
    public String net;
    public Property confTag;
    public Property intTag;
    public Property subjTag;
    public Property suspEnv;
    public Property timestamp;
    public Property counter;


    public PropagationRule() {
        Model model = ModelFactory.createDefaultModel();
        prefRule = "http://w3id.org/sepses/vocab/rule#";
        prefix = "http://w3id.org/sepses/vocab/event/log#";
        confTag = model.createProperty(prefRule + "confTag");
        intTag = model.createProperty(prefRule + "intTag");
        subjTag = model.createProperty(prefRule + "subjTag");
        suspEnv = model.createProperty(prefRule + "suspEnv");
        timestamp = model.createProperty(prefix + "timestamp");
        counter = model.createProperty(prefRule + "counter");
    }

    public void loadTag(Model jsonModel, String subject, String exec, String objectString, String propagation) {
        if (!Objects.equals(propagation, "false")) {
            subjLoad(jsonModel, subject, exec, objectString);
            intRead(jsonModel, subject, exec, objectString);
            confRead(jsonModel, subject, exec, objectString);
        }
    }


    public void readTag(Model jsonModel, String subject, String exec, String objectString, String propagation) {
        if (!Objects.equals(propagation, "false")) {
            intRead(jsonModel, subject, exec, objectString);
            confRead(jsonModel, subject, exec, objectString);
        }
    }

    public void writeTag(Model jsonModel, String subject, String exec, String objectString, String propagation) {
        if (!Objects.equals(propagation, "false")) {
            confWrite(jsonModel, subject, exec, objectString);
            intWrite(jsonModel, subject, exec, objectString);
        }
    }

    public void writeTagWithAttenuation(Model jsonModel, String subject, String exec, String objectString, double ab, double ae, String propagation) {
        if (!Objects.equals(propagation, "false")) {
            confWriteAtten(jsonModel, subject, exec, objectString, ab, ae);
            intWriteAtten(jsonModel, subject, exec, objectString, ab, ae);
        }
    }

    public void receiveTag(Model jsonModel, String subject, String exec, String objectString, String propagation) {
        if (!Objects.equals(propagation, "false")) {
            intReceive(jsonModel, subject, exec, objectString);
            confReceive(jsonModel, subject, exec, objectString);
        }
    }

    public void sendTag(Model jsonModel, String subject, String exec, String objectString, String propagation) {
        if (!Objects.equals(propagation, "false")) {
            confSend(jsonModel, subject, exec, objectString);
            intSend(jsonModel, subject, exec, objectString);
        }
    }

    public void execTag(Model jsonModel, String subject, String exec, String objectString, String propagation) {
        if (!Objects.equals(propagation, "false")) {
            intExec(jsonModel, subject, exec, objectString);
            confExec(jsonModel, subject, exec, objectString);
            subjExec(jsonModel, subject, exec, objectString);
        }
    }

    //===================READ / LOAD ==============================

    public void confRead(Model jsonModel, String subject, String exec, String objectString) {
        process = "http://w3id.org/sepses/resource/proc" + subject + "#" + exec;
        file = "http://w3id.org/sepses/resource/file#" + objectString;

        Resource resPro = jsonModel.createResource(process);
        Resource resFile = jsonModel.createResource(file);
        double proConfTag = getEntityTag(jsonModel, confTag, resPro);
        double fileConfTag = getEntityTag(jsonModel, confTag, resFile);

        if (fileConfTag != proConfTag) {
            double finalValue = finalValue(fileConfTag, proConfTag);
            jsonModel.removeAll(resPro, confTag, null);
            jsonModel.addLiteral(resPro, confTag, finalValue);
        }
    }


    public void intRead(Model jsonModel, String subject, String exec, String objectString) {
        process = "http://w3id.org/sepses/resource/proc" + subject + "#" + exec;
        file = "http://w3id.org/sepses/resource/file#" + objectString;
        Resource resPro = jsonModel.createResource(process);
        Resource resFile = jsonModel.createResource(file);

        double proIntTag = getEntityTag(jsonModel, intTag, resPro);
        double fileIntTag = getEntityTag(jsonModel, intTag, resFile);
        if (fileIntTag != proIntTag) {
            double nit = finalValue(fileIntTag, proIntTag);
            jsonModel.removeAll(resPro, intTag, null);
            jsonModel.addLiteral(resPro, intTag, nit);
        }
    }

    //===================ONLY LOAD ==============================
    public void subjLoad(Model jsonModel, String subject, String exec, String objectString) {

        process = "http://w3id.org/sepses/resource/proc" + subject + "#" + exec;
        file = "http://w3id.org/sepses/resource/file#" + objectString;

        Resource resPro = jsonModel.createResource(process);
        Resource resFile = jsonModel.createResource(file);
        double rsst = getEntityTag(jsonModel, subjTag, resPro);
        double rost = getEntityTag(jsonModel, subjTag, resFile);
        if (rost != rsst) {
            double nsst = finalValue(rsst, rost);
            jsonModel.removeAll(resPro, subjTag, null);
            jsonModel.addLiteral(resPro, subjTag, nsst);
        }
    }

    //===================RECEIVE ==============================

    public void confReceive(Model jsonModel, String subject, String exec, String objectString) {

        process = "http://w3id.org/sepses/resource/proc" + subject + "#" + exec;
        net = "http://w3id.org/sepses/resource/soc#" + objectString;

        Resource resPro = jsonModel.createResource(process);
        Resource resNet = jsonModel.createResource(net);
        double proConfTag = getEntityTag(jsonModel, confTag, resPro);
        double netConfTag = getEntityTag(jsonModel, confTag, resNet);

        if (netConfTag != proConfTag) {
            double finalValue = finalValue(netConfTag, proConfTag);
            jsonModel.removeAll(resPro, confTag, null);
            jsonModel.addLiteral(resPro, confTag, finalValue);
        }
    }


    public void intReceive(Model jsonModel, String subject, String exec, String objectString) {
        process = "http://w3id.org/sepses/resource/proc" + subject + "#" + exec;
        net = "http://w3id.org/sepses/resource/soc#" + objectString;
        Resource resPro = jsonModel.createResource(process);
        Resource resNet = jsonModel.createResource(net);

        double proIntTag = getEntityTag(jsonModel, intTag, resPro);
        double netIntTag = getEntityTag(jsonModel, intTag, resNet);

        if (netIntTag != proIntTag) {
            double finalValue = finalValue(netIntTag, proIntTag);
            jsonModel.removeAll(resPro, intTag, null);
            jsonModel.addLiteral(resPro, intTag, finalValue);
        }
    }

    //================SEND===========================

    public void confSend(Model jsonModel, String subject, String exec, String objectString) {
        process = "http://w3id.org/sepses/resource/proc" + subject + "#" + exec;
        net = "http://w3id.org/sepses/resource/soc#" + objectString;

        Resource resPro = jsonModel.createResource(process);
        Resource resNet = jsonModel.createResource(net);

        double proSubTag = getEntityTag(jsonModel, subjTag, resPro);
        double proConfTag = getEntityTag(jsonModel, confTag, resPro);
        double netConfTag = getEntityTag(jsonModel, confTag, resNet);
        boolean proSuspEnv = getSuspEnvTag(jsonModel, suspEnv, resPro);

        if (proSubTag >= 0.5) {
            //benign
            if (netConfTag != proConfTag) {
                double finalVal = finalValue(proConfTag + 0.2, netConfTag);
                if (finalVal != netConfTag) {
                    jsonModel.removeAll(resNet, confTag, null);
                    jsonModel.addLiteral(resNet, confTag, finalVal);
                }
            }
        } else {
            if (!proSuspEnv) {
                //suspect
                if (netConfTag != proConfTag) {
                    double finalVal = finalValue(proConfTag, netConfTag);
                    jsonModel.removeAll(resNet, confTag, null);
                    jsonModel.addLiteral(resNet, confTag, finalVal);
                }
            } else {
                //suspect env
                if (netConfTag != proConfTag) {
                    double finalVal = finalValue(proConfTag + 0.1, netConfTag);
                    if (finalVal != netConfTag) {
                        jsonModel.removeAll(resNet, confTag, null);
                        jsonModel.addLiteral(resNet, confTag, finalVal);
                    }
                }
            }
        }
    }

    public void intSend(Model jsonModel, String subject, String exec, String objectString) {
        process = "http://w3id.org/sepses/resource/proc" + subject + "#" + exec;
        net = "http://w3id.org/sepses/resource/soc#" + objectString;

        Resource respro = jsonModel.createResource(process);
        Resource resnet = jsonModel.createResource(net);

        double rsst = getEntityTag(jsonModel, subjTag, respro);
        double rsit = getEntityTag(jsonModel, intTag, respro);
        double roit = getEntityTag(jsonModel, intTag, resnet);
        boolean rsenv = getSuspEnvTag(jsonModel, suspEnv, respro);

        if (rsst >= 0.5) {
            //benign
            if (roit != rsit) {
                double noit = finalValue(rsit + 0.2, roit);
                if (noit != roit) {
                    jsonModel.removeAll(resnet, intTag, null);
                    jsonModel.addLiteral(resnet, intTag, noit);
                }
            }
        } else {
            if (!rsenv) {
                //suspect
                if (roit != rsit) {
                    double noit = finalValue(rsit, roit);
                    jsonModel.removeAll(resnet, intTag, null);
                    jsonModel.addLiteral(resnet, intTag, noit);
                }
            } else {
                //suspect env
                if (roit != rsit) {
                    double noit = finalValue(rsit + 0.1, roit);
                    if (noit != roit) {
                        jsonModel.removeAll(resnet, intTag, null);
                        jsonModel.addLiteral(resnet, intTag, noit);
                    }
                }
            }
        }

    }

    //================WRITE===========================

    public void confWrite(Model jsonModel, String subject, String exec, String objectString) {
        process = "http://w3id.org/sepses/resource/proc" + subject + "#" + exec;
        file = "http://w3id.org/sepses/resource/file#" + objectString;

        Resource resPro = jsonModel.createResource(process);
        Resource resFile = jsonModel.createResource(file);

        double proSubTag = getEntityTag(jsonModel, subjTag, resPro);
        double proConfTag = getEntityTag(jsonModel, confTag, resPro);
        double fileConfTag = getEntityTag(jsonModel, confTag, resFile);
        boolean proSusEnv = getSuspEnvTag(jsonModel, suspEnv, resPro);

        if (proSubTag >= 0.5) {
            //benign
            if (fileConfTag != proConfTag) {
                double finalValue = finalValue(proConfTag, fileConfTag);
                if (finalValue != fileConfTag) {
                    jsonModel.removeAll(resFile, confTag, null);
                    jsonModel.addLiteral(resFile, confTag, finalValue);
                }
            }
        } else {
            if (!proSusEnv) {
                if (fileConfTag != proConfTag) {
                    double finalValue = finalValue(proConfTag, fileConfTag);
                    jsonModel.removeAll(resFile, confTag, null);
                    jsonModel.addLiteral(resFile, confTag, finalValue);
                }
            } else {
                //suspect env
                if (fileConfTag != proConfTag) {
                    double finalValue = finalValue(proConfTag, fileConfTag);
                    if (finalValue != fileConfTag) {
                        jsonModel.removeAll(resFile, confTag, null);
                        jsonModel.addLiteral(resFile, confTag, finalValue);
                    }
                }
            }
        }
    }


    public void intWrite(Model jsonModel, String subject, String exec, String objectString) {
        process = "http://w3id.org/sepses/resource/proc" + subject + "#" + exec;
        file = "http://w3id.org/sepses/resource/file#" + objectString;

        Resource resPro = jsonModel.createResource(process);
        Resource resFile = jsonModel.createResource(file);

        double proSubjTag = getEntityTag(jsonModel, subjTag, resPro);
        double proIntTag = getEntityTag(jsonModel, intTag, resPro);
        double fileIntTag = getEntityTag(jsonModel, intTag, resFile);
        boolean suspEnv = getSuspEnvTag(jsonModel, this.suspEnv, resPro);

        if (proSubjTag >= 0.5) {
            //benign
            if (fileIntTag != proIntTag) {
                double finalValue = finalValue(proIntTag, fileIntTag);
                if (finalValue != fileIntTag) {
                    jsonModel.removeAll(resFile, intTag, null);
                    jsonModel.addLiteral(resFile, intTag, finalValue);
                }
            }
        } else {
            if (!suspEnv) {
                if (fileIntTag != proIntTag) {
                    double finalValue = finalValue(proIntTag, fileIntTag);
                    jsonModel.removeAll(resFile, intTag, null);
                    jsonModel.addLiteral(resFile, intTag, finalValue);
                }
            } else {
                if (fileIntTag != proIntTag) {
                    double finalValue = finalValue(proIntTag, fileIntTag);
                    if (finalValue != fileIntTag) {
                        jsonModel.removeAll(resFile, intTag, null);
                        jsonModel.addLiteral(resFile, intTag, finalValue);
                    }
                }
            }
        }
    }

    //----------------------WRITE WITH ATTENUATION----------------------------------------
    public void confWriteAtten(Model jsonModel, String subject, String exec, String objectString, double ab, double ae) {
        process = "http://w3id.org/sepses/resource/proc" + subject + "#" + exec;
        file = "http://w3id.org/sepses/resource/file#" + objectString;

        Resource resPro = jsonModel.createResource(process);
        Resource resFile = jsonModel.createResource(file);

        double proSubjTag = getEntityTag(jsonModel, subjTag, resPro);
        double proConfTag = getEntityTag(jsonModel, confTag, resPro);
        double fileConfTag = getEntityTag(jsonModel, confTag, resFile);
        boolean proSuspEnv = getSuspEnvTag(jsonModel, suspEnv, resPro);

        if (proSubjTag >= 0.5) {
            //benign
            if (fileConfTag != proConfTag) {
                double finalValue = finalValue(proConfTag + ab, fileConfTag);
                if (finalValue != fileConfTag) {
                    jsonModel.removeAll(resFile, confTag, null);
                    jsonModel.addLiteral(resFile, confTag, finalValue);
                }
            }
        } else {
            if (!proSuspEnv) {
                if (fileConfTag != proConfTag) {
                    double finalValue = finalValue(proConfTag, fileConfTag);
                    jsonModel.removeAll(resFile, confTag, null);
                    jsonModel.addLiteral(resFile, confTag, finalValue);
                }
            } else {
                //suspect env
                if (fileConfTag != proConfTag) {
                    double finalValue = finalValue(proConfTag + ae, fileConfTag);
                    if (finalValue != fileConfTag) {
                        jsonModel.removeAll(resFile, confTag, null);
                        jsonModel.addLiteral(resFile, confTag, finalValue);
                    }
                }
            }
        }
    }

    public void intWriteAtten(Model jsonModel, String subject, String exec, String objectString, double ab, double ae) {
        process = "http://w3id.org/sepses/resource/proc" + subject + "#" + exec;
        file = "http://w3id.org/sepses/resource/file#" + objectString;

        Resource resPro = jsonModel.createResource(process);
        Resource resFile = jsonModel.createResource(file);

        double proSubTag = getEntityTag(jsonModel, subjTag, resPro);
        double proIntTag = getEntityTag(jsonModel, intTag, resPro);
        double fileIntTag = getEntityTag(jsonModel, intTag, resFile);
        boolean proEnv = getSuspEnvTag(jsonModel, suspEnv, resPro);


        if (proSubTag >= 0.5) {
            //benign
            if (fileIntTag != proIntTag) {
                double finalValue = finalValue(proIntTag + ab, fileIntTag);
                if (finalValue != fileIntTag) {
                    jsonModel.removeAll(resFile, intTag, null);
                    jsonModel.addLiteral(resFile, intTag, finalValue);
                }
            }
        } else {
            if (!proEnv) {
                if (fileIntTag != proIntTag) {
                    double finalValue = finalValue(proIntTag, fileIntTag);
                    jsonModel.removeAll(resFile, intTag, null);
                    jsonModel.addLiteral(resFile, intTag, finalValue);
                }
            } else {
                if (fileIntTag != proIntTag) {
                    double finalValue = finalValue(proIntTag + ae, fileIntTag);
                    if (finalValue != fileIntTag) {
                        jsonModel.removeAll(resFile, intTag, null);
                        jsonModel.addLiteral(resFile, intTag, finalValue);
                    }
                }
            }
        }
    }

    //================EXEC===========================
    public void subjExec(Model jsonModel, String subject, String exec, String objectString) {

        process = "http://w3id.org/sepses/resource/proc" + subject + "#" + exec;
        file = "http://w3id.org/sepses/resource/file#" + objectString;

        Resource resPro = jsonModel.createResource(process);
        Resource resFile = jsonModel.createResource(file);
        double rsst = getEntityTag(jsonModel, subjTag, resPro);
        double roit = getEntityTag(jsonModel, intTag, resFile);
        boolean rsenv = getSuspEnvTag(jsonModel, suspEnv, resPro);

        if (rsst >= 0.5) {
            //benign
            if (roit != rsst) {
                jsonModel.removeAll(resPro, subjTag, null);
                jsonModel.addLiteral(resPro, subjTag, roit);
            }
        } else {
            if (!rsenv) {
                //suspect
                if (roit != rsst) {
                    double nsst = finalValue(rsst, roit);
                    jsonModel.removeAll(resPro, subjTag, null);
                    jsonModel.addLiteral(resPro, subjTag, nsst);
                    jsonModel.addLiteral(resPro, suspEnv, true);
                }
            } else {
                //suspect env
                if (roit != rsst) {
                    jsonModel.removeAll(resPro, subjTag, null);
                    jsonModel.addLiteral(resPro, subjTag, roit);
                }
            }
        }
    }


	public void confExec(Model jsonModel, String subject, String exec, String objectString) {
		process = "http://w3id.org/sepses/resource/proc" + subject + "#" + exec;
		file = "http://w3id.org/sepses/resource/file#" + objectString;

		Resource resPro = jsonModel.createResource(process);
		Resource resFile = jsonModel.createResource(file);

		double proSubTag = getEntityTag(jsonModel, subjTag, resPro);
		double proConfTag = getEntityTag(jsonModel, confTag, resPro);
		double fileConfTag = getEntityTag(jsonModel, confTag, resFile);

		if (proSubTag < 0.5) {
			//suspect
			if (fileConfTag != proConfTag) {
				double nsct = finalValue(proConfTag, fileConfTag);
				jsonModel.removeAll(resPro, confTag, null);
				jsonModel.addLiteral(resPro, confTag, nsct);
			}
		} else {
			//benign
			double nrsst = 1.0;
			jsonModel.removeAll(resPro, confTag, null);
			jsonModel.addLiteral(resPro, confTag, nrsst);
		}
	}

	public void intExec(Model jsonModel, String subject, String exec, String objectString) {
		process = "http://w3id.org/sepses/resource/proc" + subject + "#" + exec;
		file = "http://w3id.org/sepses/resource/file#" + objectString;

		Resource resPro = jsonModel.createResource(process);
		Resource resFile = jsonModel.createResource(file);

		double proSubTag = getEntityTag(jsonModel, subjTag, resPro);
		double proIntTag = getEntityTag(jsonModel, intTag, resPro);
		double fileIntTag = getEntityTag(jsonModel, intTag, resFile);

		if (proSubTag < 0.5) {
			//suspect
			if (fileIntTag != proIntTag) {
				double nsit = finalValue(proIntTag, fileIntTag);
				jsonModel.removeAll(resPro, intTag, null);
				jsonModel.addLiteral(resPro, intTag, nsit);
			}
		} else {
			//benign
			jsonModel.removeAll(resPro, intTag, null);
			jsonModel.addLiteral(resPro, intTag, fileIntTag);
		}
	}


    //================FORK============
	public void forkTag(Model jsonModel, String prevProcess, String process) {
		String prevProc = "http://w3id.org/sepses/resource/proc" + prevProcess;
		process = "http://w3id.org/sepses/resource/proc" + process;

		Resource resPrevPro = jsonModel.createResource(prevProc);
		Resource resPro = jsonModel.createResource(process);

		double preProSubTag = getEntityTag(jsonModel, subjTag, resPrevPro);
		double preProConfTag = getEntityTag(jsonModel, confTag, resPrevPro);
		double preProIntTag = getEntityTag(jsonModel, intTag, resPrevPro);
		boolean preProEnv = getSuspEnvTag(jsonModel, suspEnv, resPrevPro);

		jsonModel.removeAll(resPro, subjTag, null);
		jsonModel.addLiteral(resPro, subjTag, preProSubTag);
		jsonModel.removeAll(resPro, confTag, null);
		jsonModel.addLiteral(resPro, confTag, preProConfTag);
		jsonModel.removeAll(resPro, intTag, null);
		jsonModel.addLiteral(resPro, intTag, preProIntTag);
		if (preProEnv) {
			jsonModel.addLiteral(resPro, suspEnv, true);
		}
	}


    public double finalValue(double s, double o) {
        return Math.min(s, o);
    }

    public double getEntityTag(Model jsonModel, Property prop, Resource entity) {
        double ptag = 1.0;
        StmtIterator iter = jsonModel.listStatements(entity, prop, (RDFNode) null);
        while (iter.hasNext()) {
            Statement s = iter.next();
            ptag = s.getObject().asLiteral().getDouble();
        }
        return ptag;
    }

    public boolean getSuspEnvTag(Model jsonModel, Property prop, Resource entity) {
        boolean suspEnv = false;
        StmtIterator iter = jsonModel.listStatements(entity, prop, (RDFNode) null);
        while (iter.hasNext()) {
            Statement s = iter.next();
            suspEnv = s.getObject().asLiteral().getBoolean();
        }
        return suspEnv;
    }

    public int getCounter(Model jsonModel, Property prop, Resource entity) {
        int counter = 0;
        StmtIterator iter = jsonModel.listStatements(entity, prop, (RDFNode) null);
        while (iter.hasNext()) {
            Statement s = iter.next();
            counter = s.getObject().asLiteral().getInt();
        }
        return counter;
    }

    public long getTimer(Model jsonModel, Property prop, Resource entity) {
        long timer = 0;
        StmtIterator iter = jsonModel.listStatements(entity, prop, (RDFNode) null);
        while (iter.hasNext()) {
            Statement s = iter.next();
            timer = s.getObject().asLiteral().getLong();
        }
        return timer;
    }

    //=============add time for subject======================
    public void putProcessTime(Model jsonModel, String subject, String exec, long ts) {
        process = "http://w3id.org/sepses/resource/proc" + subject + "#" + exec;
        Resource resPro = jsonModel.createResource(process);
        jsonModel.removeAll(resPro, timestamp, null);
        jsonModel.addLiteral(resPro, timestamp, ts);
    }

    public void putCounter(Model jsonModel, String subject, String exec) {
        process = "http://w3id.org/sepses/resource/proc" + subject + "#" + exec;

        Resource respro = jsonModel.createResource(process);
        int prevCounter = getCounter(jsonModel, counter, respro);

        jsonModel.removeAll(respro, counter, null);
        jsonModel.addLiteral(respro, counter, prevCounter + 1);

    }

    //=================decay=========================

    public void decayProcess(Model jsonModel, long timer, double period, double T) {

        String execQuery = "PREFIX : <http://w3id.org/sepses/vocab/rule#>\r\n" +
                "PREFIX log: <http://w3id.org/sepses/vocab/event/log#>\r\n" +
                "SELECT ?s ?it \r\n"
                + "WHERE {\r\n" +
                " ?s :intTag ?it.\r\n" +
                " ?s :subjTag ?st.\r\n" +
                " FILTER (?st >= 0.5) \r\n" +
                " FILTER (?it < 0.5) \r\n" +
                "}";

        QueryExecution qexec = QueryExecutionFactory.create(execQuery, jsonModel);
        ArrayList<HashMap<String, RDFNode>> list = new ArrayList<HashMap<String, RDFNode>>();

        ResultSet result = qexec.execSelect();

        while (result.hasNext()) {
            HashMap<String, RDFNode> eachres = new HashMap<String, RDFNode>();
            QuerySolution soln = result.nextSolution();
            eachres.put("s", soln.get("s"));
            eachres.put("it", soln.get("it"));
            list.add(eachres);
        }
        //System.out.println(list.size());
        for (int i = 0; i < list.size(); i++) {
            Resource s = list.get(i).get("s").asResource();
            int c = getCounter(jsonModel, counter, s);
            long t = getTimer(jsonModel, timestamp, s);
            long age = timer - t;
            //System.out.println(c+" : "+age);
            double periodNano = period * 1000000000;
            //System.out.println(c+" "+age+" : "+(c*periodNano));
            if (age >= (c * periodNano)) {
                //System.out.println("yes, adult!");
                jsonModel.removeAll(s, counter, null);
                jsonModel.addLiteral(s, counter, c + 1);
                double it = list.get(i).get("it").asLiteral().getDouble();
                double decayRateIntTag = (it * period) + ((1 - period) * T);
                double nit = 0;
                //System.out.println(s+"=>"+it+" => "+decayRateIntTag);
                if (it < decayRateIntTag) {
                    nit = decayRateIntTag;
                    jsonModel.removeAll(s, intTag, null);
                    jsonModel.addLiteral(s, intTag, nit);
                }
            }
        }
    }

    public void decayIndividualProcess(Model jsonModel, String proc, long timer, double period, double Tb, double Te) {
        process = "http://w3id.org/sepses/resource/proc" + proc;
        Resource s = jsonModel.createResource(process);
        
        double proSubTag = getEntityTag(jsonModel, subjTag, s);
        long t = getTimer(jsonModel, timestamp, s);
        long age = timer - t;
        double periodNano = period * 1000000000;

        //1. decay data integrity
        double intTag = getEntityTag(jsonModel, this.intTag, s);
        if (intTag < 0.5) { //get only low data tag integrity of subj
            if (proSubTag >= 0.5) {  //if subject is benign
                if (age >= periodNano) {
                    double decayRateIntTag = (intTag * period) + ((1 - period) * Tb); //add decay rate
                    if (intTag < decayRateIntTag) {
                        jsonModel.removeAll(s, this.intTag, null);
                        jsonModel.addLiteral(s, this.intTag, decayRateIntTag);
                    }
                }
            } else {  //if subject is suspect
                boolean susEnv = getSuspEnvTag(jsonModel, suspEnv, s);
                if (susEnv) { //if suspect in environment
                    if (age >= periodNano) {
                        double decayRateIntTag = (intTag * period) + ((1 - period) * Te);
                        if (intTag < decayRateIntTag) {
                            jsonModel.removeAll(s, this.intTag, null);
                            jsonModel.addLiteral(s, this.intTag, decayRateIntTag);
                        }
                    }
                }
            }
        }
        //2. decay data confidentiality
        double congTag = getEntityTag(jsonModel, confTag, s);
        if (congTag < 0.5) { //get only low data tag integrity of subj
            if (proSubTag >= 0.5) {  //if subject is benign
                if (age >= periodNano) {
                    double decayRateConfTag = (congTag * period) + ((1 - period) * Tb); //add decay rate
                    if (congTag < decayRateConfTag) {
                        jsonModel.removeAll(s, confTag, null);
                        jsonModel.addLiteral(s, confTag, decayRateConfTag);
                    }
                }
            } else {  //if subject is suspect
                boolean subEnv = getSuspEnvTag(jsonModel, suspEnv, s);
                if (subEnv) { //if suspect in environment
                    if (age >= periodNano) {
                        double decayRateConfTag = (congTag * period) + ((1 - period) * Te);
                        if (congTag < decayRateConfTag) {
                            jsonModel.removeAll(s, confTag, null);
                            jsonModel.addLiteral(s, confTag, decayRateConfTag);
                        }
                    }
                }
            }
        }
    }
}