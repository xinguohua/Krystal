package sepses.krystal.helper;

import org.apache.commons.io.IOUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.InputStream;
import java.nio.file.Paths;
import java.util.Arrays;

public enum GraphDBStorage implements Storage {

    INSTANCE();

    private static final Logger log = LoggerFactory.getLogger(GraphDBStorage.class);

    public static GraphDBStorage getInstance() {
        return INSTANCE;
    }

    public void storeData(String file, String endpoint, String namegraph, Boolean isUseAuth, String user,
            String pass) {
        try {
            log.info(file);
            if (!isUseAuth) {
                log.error("not handled yet");
                return;
            }

            long start = System.currentTimeMillis() / 1000;

            //curl -X PUT -H "Content-Type:application/x-turtle" -T experiment/ontology/log-ontology.ttl "http://localhost:7200/repositories/Krystal/rdf-graphs/service?graph=http://w3id.org/sepses/graph/cadets"
            String[] command = {
                    "curl",
                    "-X", "PUT",
                    "-H", "Content-Type:application/x-turtle",
                    "-T",  file,
                    String.format("%s/rdf-graphs/service?graph=%s", endpoint, namegraph)
            };
            System.out.println(Arrays.toString(command));
            Process process = Runtime.getRuntime().exec(command);
            InputStream is = process.getInputStream();
            IOUtils.copy(is, System.out);
            is.close();
            log.info("Data stored successfully");

            long end = System.currentTimeMillis() / 1000;
            log.info("Writing process for '" + file + "' took " + (end - start) + " seconds");
        } catch (Exception e) {
            log.error(e.getMessage(), e);
        }

    }

	public void replaceData(String file, String endpoint, String namegraph, Boolean isUseAuth, String user,
			String pass) {
		 try {
	            log.info(file);
	            if (!isUseAuth) {
	                log.error("not handled yet");
	                return;
	            }

	            long start = System.currentTimeMillis() / 1000;         
	            String command = "curl -X PUT -H \"Content-Type:application/x-turtle\" -T "+file+"  -G --data-urlencode \"graph="+namegraph+"\" "+endpoint+"/rdf-graphs/service";            	
	           // System.out.println(command);
	            Process process = Runtime.getRuntime().exec(command);
	            InputStream is = process.getInputStream();
	            IOUtils.copy(is, System.out);
	            is.close();
	            log.info("Data stored successfully");

	            long end = System.currentTimeMillis() / 1000;
	            log.info("Writing process for '" + file + "' took " + (end - start) + " seconds");
	        } catch (Exception e) {
	            log.error(e.getMessage(), e);
	        }
		
	}

}
