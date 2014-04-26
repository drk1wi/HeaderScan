package burp;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.Map;
import javax.swing.JMenuItem;
import k1wi.HeaderTab;


public class BurpExtender implements IBurpExtender, IScannerCheck, IContextMenuFactory
{
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private Boolean enabled = true;
    public static final String TAB_NAME = "HeaderScan";
    public static String MENU_ITEM_TEXT = "Send request(s) to HeaderScan";
    private String[] request_headers = 
    {"X-Sfg-Data","Accept","Accept-Charset","Accept-Encoding",
        "Accept-Language","Accept-Datetime","Authorization",
        "Cache-Control","Connection","Cookie","Content-Length"
        ,"Content-MD5","Content-Type","Date" ,"Expect","From",
        "Host","If-Match","If-Modified-Since","If-None-Match",
        "If-Range","If-Unmodified-Since","Max-Forwards","Pragma",
        "Proxy-Authorization","Range","Referer","TE","Upgrade",
        "User-Agent","Via","Warning","X-Requested-With",
        "DNT","X-Forwarded-For","X-remote-IP","X-originating-IP","x-remote-addr","X-Forwarded-Proto",
        "Front-End-Https","x-att-deviceid","x-wap-profile",
        "Proxy-Connection"};
   


        
    private final LinkedHashMap<Integer,Integer> hashmap = new LinkedHashMap<Integer,Integer>();
    private PrintWriter stdout ;

   
    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks)
    {
        // keep a reference to our callbacks object
        this.callbacks = callbacks;
        
        // obtain an extension helpers object
        helpers = callbacks.getHelpers();
        
        this.stdout=new PrintWriter(callbacks.getStdout(), true);
        // set our extension name
        callbacks.setExtensionName("HeaderScan extension v.0.1");
        stdout.println("HeaderScan extension v.0.1");
        stdout.println("Author: Piotr Duszynski - piotr[at]duszynski.eu");

                        
        // register ourselves as a custom scanner check
        callbacks.registerScannerCheck(this);
        
        HeaderTab tehTab = new HeaderTab(this);
        callbacks.addSuiteTab(tehTab);
        callbacks.registerContextMenuFactory(this);
        
        
    }

    private LinkedHashMap<String,String> convertList2Map(List<String> list)
    {   
        LinkedHashMap<String, String> myMap = new LinkedHashMap<>();
        Iterator<String> iterator = list.iterator();

        String value=iterator.next() ;//ignore HTTP METHOD
        myMap.put(value,""); 
        
         while (iterator.hasNext()) {
             value=iterator.next();
    
           if( !value.isEmpty() &&  value.contains(":")){
                String[] keyValue = value.split("\\s*:\\s*");
                myMap.put(keyValue[0], keyValue[1]);
            }
            else
                myMap.put(value,"");         
       }

        return myMap;
  
    }
    
     private int getListHash(List<String> list)
    {
        List<String> local_list= new ArrayList<String>(list);
        java.util.Collections.sort(local_list);
        String result="";
        for (String value : local_list) {
            result=result+value;
        }
        return result.hashCode();
  
    }
     
    private List<String> convertMap2List(Map<String,String> map)
    {
        List<String> myList = new ArrayList<>();

        for (Map.Entry<String, String> entry : map.entrySet()) {    
            String key = entry.getKey();
            String value = entry.getValue();
                if(value.isEmpty())
                myList.add(key);
                else
                myList.add(key+":"+value);
        }
          
        return myList;
  
    }
    
    
    private boolean MapcontainsKey(Map<String,String> map, List<String> keys )
    {
        for (String key : keys) {
            if(map.containsKey(key))
                return true;
        }
        return false;
  
    }
       
    
    private List<int[]> getoheaderffsets(byte[] request, String header, String value)
    {
        List<int[]> myList = new ArrayList<int[]>();
        byte[] pattern = this.helpers.stringToBytes(header+":"+value);
        int start_offset=-1;
        int end_offset=-1;

        start_offset=this.helpers.indexOf(request,pattern,true,0,request.length);
        end_offset=start_offset+pattern.length;
        start_offset=+ header.length()+1;
        
        if(start_offset == -1)
            stdout.println("Error:Header not found!");
        int arr[]={start_offset,end_offset};
        myList.add(arr);
        
        return myList;
  
    }
   

    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse)
    {
     return null;
    }
    
    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint)
    {
        if(this.enabled == false && insertionPoint != null )
            return null;
        
        synchronized (this) {
            
        List<byte[]> requests = new ArrayList<>();
        
        byte[] request = baseRequestResponse.getRequest();

        // make a request containing our injection test in the insertion point
        IHttpRequestResponse checkRequestResponse = callbacks.makeHttpRequest(
                baseRequestResponse.getHttpService(), request);
        
        IRequestInfo irequest = this.helpers.analyzeRequest(baseRequestResponse);
        String string_request = new String(baseRequestResponse.getRequest());
        String messageBody = string_request.substring(irequest.getBodyOffset());
        List<String> headers = irequest.getHeaders();
        
        /// Check if already processed        
        int hash=(irequest.getUrl().getHost()+irequest.getUrl().getPath()).hashCode();
        if(hashmap.containsKey(hash))
        {
          stdout.println("Request HOST+PATH already processed!");
          return null;
        }
        else
            hashmap.put(hash,hash);
        
       
        Map<String, String> headersMap = this.convertList2Map(headers);

        
        if(headersMap.containsValue("FUZZME"))
        {
          return null;
        }
        
        stdout.println("Original request!:");
        stdout.println(this.helpers.bytesToString(request));

        for (String header : request_headers) {  
            if(headersMap.containsKey(header))
                continue;
            else
            {
                
              LinkedHashMap<String, String> modheadersMap = new LinkedHashMap<String, String>(headersMap); 
              modheadersMap.put(header,"FUZZME");
              List<String> mod_headers =  this.convertMap2List(modheadersMap);
                
              hashmap.put(this.getListHash(mod_headers), this.getListHash(mod_headers));
              byte[] mod_request=this.helpers.buildHttpMessage(mod_headers, messageBody.getBytes());
              //
              stdout.println("Modified request!:");
              stdout.println(this.helpers.bytesToString(mod_request));
              //
              String host = baseRequestResponse.getHttpService().getHost();
              int port = baseRequestResponse.getHttpService().getPort();
              Boolean serviceIsHttps = baseRequestResponse.getHttpService().getProtocol() == "https" ? true : false;
              List<int[]> offsets =  this.getoheaderffsets(mod_request,header,"FUZZME");
              this.callbacks.doActiveScan(host,port,serviceIsHttps,mod_request,offsets);  
              
            }
        }
                
        return null;
        }
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue)
    {
        // This method is called when multiple issues are reported for the same URL 
        // path by the same extension-provided check. The value we return from this 
        // method determines how/whether Burp consolidates the multiple issues
        // to prevent duplication
        //
        // Since the issue name is sufficient to identify our issues as different,
        // if both issues have the same name, only report the existing issue
        // otherwise report both issues
        if (existingIssue.getIssueName().equals(newIssue.getIssueName()))
            return -1;
        else return 0;
    }
    
   
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {

        final IHttpRequestResponse requests[] = invocation.getSelectedMessages();


        List<JMenuItem> ret = new LinkedList<JMenuItem>();


        JMenuItem menuItem = new JMenuItem(MENU_ITEM_TEXT);


        menuItem.addActionListener(new ActionListener(){
        public void actionPerformed(ActionEvent arg0) {

        if(arg0.getActionCommand().equals(MENU_ITEM_TEXT)){
                PrintWriter stdout = new PrintWriter(callbacks.getStdout(), true);
                for( IHttpRequestResponse request : requests)
                        {
                            doActiveScan(request, null);
                        }
        }
        }
        });

        ret.add(menuItem);


return(ret);

}
    
    public void enable()
    {
        stdout.println("Plugin enabled!");
        this.enabled=true;
    }
    
    public void disable()
    {
        stdout.println("Plugin disabled!");
        this.enabled=false;
    }
    
    public boolean  getstate()
    {
        return this.enabled;
    }
        
        
}





     




