from burp import IBurpExtender
from burp import IExtensionStateListener
from burp import IHttpListener
from java.lang import Thread
from javax.swing import JFrame, JLabel, JTable,JScrollPane,JSplitPane,JTextArea,KeyStroke,AbstractAction
from javax.swing.table import DefaultTableModel
from java.awt import BorderLayout

import re
import gc

class WorkThread(Thread):
    def __init__(self,burpCallbacks,plugin):
        self.burpCallbacks = burpCallbacks
        self.plugin = plugin
        self.uniqueMatches = {}
        Thread.__init__(self)


    def _getRegexStrings(self):
        return self.plugin.guiExpressionsTextArea.getText().split("\n");

    def _addMatchIfUnique(self,match):
        
        #Ensure we are adding string to dictioanry, not 
        #String objects
        if match not in self.uniqueMatches:
            self.uniqueMatches[match] = True
            self.plugin.dataTableModel.addRow([match])

    # Search matches given regexes.
    # We take an array of regexes so we don't have to fetch
    # responses multiple times
    def _searchForRegexes(self,compiledRegexes):
        requestResponses = self.burpCallbacks.getProxyHistory()

        requestInspectedCount = 0
        for requestResponse in requestResponses:


            if Thread.interrupted():
                break

            response = requestResponse.getResponse()
            if response:
                
                try:
                    # TODO not all requests should be treated as utf-8
                    responseStr = self.burpCallbacks.helpers.bytesToString(response).encode('utf-8')

                # TODO notify user this failed
                except:
                    continue

                for regex in compiledRegexes:
                    matches = re.finditer(regex,responseStr) 
                    for m in matches:
                        #Clip responses to 2000 characters
                        self._addMatchIfUnique(m.group(0)[:2000])
                        

        gc.collect()


    def run(self):

        regexStrings = self._getRegexStrings()
        compiledRegexes = []
        regexErrors = []

        #Check regexes are valid
        for regex in regexStrings:
            if len(regex) > 0 and regex[0] != ";":
                try: 
                     compiledRegexes.append(re.compile(regex))
                except Exception as e:
                    regexErrors.append("Regex Error: " + str(e) + " in " + regex)


        if len(regexErrors):
            for regexError in regexErrors:
                self.plugin.dataTableModel.addRow([regexError])
        else:             
            self._searchForRegexes(compiledRegexes)


class BurpExtender(IBurpExtender,IExtensionStateListener):
    def registerExtenderCallbacks( self, callbacks):

        self._helpers = callbacks.getHelpers()
        self._callbacks = callbacks
        self._initGui()
        self.thread = None


        self._addRegex(r";Proxy Grepper")
        self._addRegex(r";Type one regex per line, then shift+enter to execute")
        self._addRegex(r";If regex needs to start with comment character ; , start expression with [;]")
        self._addRegex(r";Currently only matches text in HTTP responses.")
        self._addRegex(r"")
        self._addRegex(r";Example regex")
        self._addRegex(r"cgi-bin[^'\"]+")

        self._callbacks.registerExtensionStateListener(self)


    def _addRegex(self,regexString):
        return self.guiExpressionsTextArea.append(regexString+"\n")

    def runRegexScan(self):
        if self.thread:
            self.thread.interrupt()
            self.thread.join()

        self.dataTableModel.setRowCount(0)
        self.thread = WorkThread(self._callbacks,self)
        self.thread.start()

    def extensionUnloaded(self):
        if(self.thread):
            self.thread.interrupt()
            self.thread.join()
        self.thread = None

        self.frame.setVisible(False)
        self.frame.dispose()
        return

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if messageIsRequest:
            return
        #print(messageInfo.getResponse())

        
    def _initGui(self):
        self.frame = JFrame("Proxy Grepper")
        self.frame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);

        
        #Create Matched Expression scrollable tabel
        tableColumns=["Matched Expression"]
        self.dataTableModel = DefaultTableModel(tableColumns,0)

        self.table = JTable(self.dataTableModel)
        self.table.setAutoCreateRowSorter(True)
        scrollPane = JScrollPane(self.table)
        scrollPane.setBounds(0,0,400,300)
        scrollPane.setVisible(True)

        #Create Regex InputField
        regexTableColumns=["Expressions"]
        self.guiExpressionsTextArea = JTextArea(50,50)
        scrollPaneRegex = JScrollPane(self.guiExpressionsTextArea)
        scrollPaneRegex.setBounds(0,0,400,300)
        scrollPaneRegex.setVisible(True)

        #Regex matches on left, regex editor on right
        splitPane = JSplitPane(JSplitPane.HORIZONTAL_SPLIT,scrollPane,scrollPaneRegex)

        self.frame.getContentPane().add(splitPane, BorderLayout.CENTER);
        self.frame.setSize(400,300)
        self.frame.setVisible(True)
    
    
        #Shift+Enter triggers new run
        inputMap = self.guiExpressionsTextArea.getInputMap()
        shiftEnterKeyStroke = KeyStroke.getKeyStroke("shift ENTER");
        inputMap.put(shiftEnterKeyStroke,"RUN-REGEX")
        actionMap = self.guiExpressionsTextArea.getActionMap()

        class RegexFieldActionHandler(AbstractAction):
            def __init__(self,plugin):
                self.plugin = plugin

            def actionPerformed(self,actionEvent):
                self.plugin.runRegexScan()

        actionMap.put("RUN-REGEX", RegexFieldActionHandler(self))

        
