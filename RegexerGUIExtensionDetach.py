from burp import IBurpExtender
from burp import ITab

from java.lang import Integer
from java.lang import Object
from java.lang import Short
from java.lang import String

from javax.swing import BorderFactory
from javax.swing import GroupLayout
from javax.swing import LayoutStyle
from javax.swing import WindowConstants
from javax.swing import UnsupportedLookAndFeelException

from javax.swing import JButton
from javax.swing import JFrame
from javax.swing import JLabel
from javax.swing import JOptionPane
from javax.swing import JPanel
from javax.swing import JScrollPane
from javax.swing import JTable
from javax.swing import JTextField

from javax.swing.table import DefaultTableModel
from java.awt import Color
from java.awt.event import MouseListener
import sys
try:
    from exceptions_fix import FixBurpExceptions
except ImportError:
    pass


class BurpExtender(IBurpExtender, ITab):

    def registerExtenderCallbacks(self, callbacks):

        try:
            sys.stdout = callbacks.getStdout()
        except:
            pass

        callbacks.setExtensionName("RegexerGUI")
        callbacks.addSuiteTab(self)

    def getTabCaption(self):
        return "RegexerGUI"

    def getUiComponent(self):
        tableData = [
            [1, "1st rule", "://"],
            [2, "2nd rule", "url="],
            [3, "3rd rule", "<a link="]
        ]
        tableColumns = ["#", "Rule Name", "Regex Rule"]
        
        regexerGui = RegexerGUI(tableData, tableColumns)
        # regexerGuiEdit = RegexerGUIEdit()
        # regexerGuiEdit.pack()
        # regexerGuiEdit.show()
        return regexerGui.panel


class RegexerGUI(JFrame):

    def __init__(self, data, columns):
        self.jScrollPane1 = JScrollPane()
        self.jTableRegex = JTable()
        self.jButtonAdd = JButton("Add", actionPerformed=self.handleJButtonAdd)
        self.jButtonRemove = JButton("Remove", actionPerformed=self.handleJButtonRemove)
        self.jButtonEdit = JButton("Edit", actionPerformed=self.handleJButtonEdit)

        self.jTableRegex = RegexTable(data, columns)
        self.jScrollPane1.setViewportView(self.jTableRegex)

        self.panel = JPanel()
        layout = GroupLayout(self.panel)
        self.panel.setLayout(layout)
        layout.setAutoCreateGaps(True)
        layout.setHorizontalGroup(
            layout.createParallelGroup(GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.TRAILING, False)
                    .addComponent(self.jButtonEdit, GroupLayout.Alignment.LEADING, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(self.jButtonAdd, GroupLayout.Alignment.LEADING, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(self.jButtonRemove, GroupLayout.PREFERRED_SIZE, 86, GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(self.jScrollPane1, GroupLayout.DEFAULT_SIZE, 777, Short.MAX_VALUE))
        )
        layout.setVerticalGroup(
            layout.createParallelGroup(GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                    .addComponent(self.jScrollPane1, GroupLayout.PREFERRED_SIZE, 0, Short.MAX_VALUE)
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(self.jButtonAdd, GroupLayout.PREFERRED_SIZE, 28, GroupLayout.PREFERRED_SIZE)
                        .addGap(4, 4, 4)
                        .addComponent(self.jButtonEdit, GroupLayout.PREFERRED_SIZE, 28, GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(self.jButtonRemove, GroupLayout.PREFERRED_SIZE, 28, GroupLayout.PREFERRED_SIZE)
                        .addGap(0, 182, Short.MAX_VALUE))))
        )             

    def handleJButtonAdd(self, event):
        regexerGUIEdit = RegexerGUIEdit(self.jTableRegex)
        regexerGUIEdit.pack()
        regexerGUIEdit.show()

    def handleJButtonRemove(self, event):
        if(self.jTableRegex.getSelectedRow() != -1):
            self.jTableRegex.removeRow(self.jTableRegex.getSelectedRow())
            JOptionPane.showMessageDialog(None, "Selected row deleted successfully")
        print("Button '{}' clicked".format(event.source.text))

    def handleJButtonEdit(self, event):
        print("Button '{}' clicked".format(event.source.text))


class RegexerGUIEdit(JFrame):

    def __init__(self, jTableRegex):
        self.jLabel1 = JLabel()
        self.jLabel1.setText("Specify the details of the regex rule.")
        
        self.jLabel2 = JLabel()
        self.jLabel2.setText("Rule Name:")
        
        self.jLabel3 = JLabel()
        self.jLabel3.setText("Regex:")

        self.jTextFieldRuleName = JTextField()
        self.jTextFieldRegex = JTextField()
        
        self.jButtonOK = JButton("OK", actionPerformed=self.addRegex)
        self.jButtonCancel = JButton("Cancel", actionPerformed=self.closeRegexerGUIEdit)

        self.jTableRegex = jTableRegex

        self.setTitle("Add Regex Rule")

        self.jTextFieldRuleName.setToolTipText("")
        self.jTextFieldRuleName.setBorder(BorderFactory.createLineBorder(Color.lightGray));
        self.jTextFieldRegex.setToolTipText("")
        self.jTextFieldRegex.setBorder(BorderFactory.createLineBorder(Color.lightGray));
        
        layout = GroupLayout(self.getContentPane())
        self.getContentPane().setLayout(layout)
        layout.setHorizontalGroup(
            layout.createParallelGroup(GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGap(20, 20, 20)
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                    .addComponent(self.jLabel1)
                    .addGroup(layout.createParallelGroup(GroupLayout.Alignment.TRAILING)
                        .addGroup(layout.createSequentialGroup()
                            .addComponent(self.jButtonOK, GroupLayout.PREFERRED_SIZE, 70, GroupLayout.PREFERRED_SIZE)
                            .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                            .addComponent(self.jButtonCancel, GroupLayout.PREFERRED_SIZE, 70, GroupLayout.PREFERRED_SIZE))
                        .addGroup(layout.createSequentialGroup()
                            .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                                .addComponent(self.jLabel2)
                                .addComponent(self.jLabel3))
                            .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                            .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING, False)
                                .addComponent(self.jTextFieldRuleName)
                                .addComponent(self.jTextFieldRegex, GroupLayout.DEFAULT_SIZE, 382, Short.MAX_VALUE)))))
                .addContainerGap(20, Short.MAX_VALUE))
        )
        layout.setVerticalGroup(
            layout.createParallelGroup(GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGap(20, 20, 20)
                .addComponent(self.jLabel1)
                .addGap(18, 18, 18)
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                    .addComponent(self.jLabel2)
                    .addComponent(self.jTextFieldRuleName, GroupLayout.PREFERRED_SIZE, 24, GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(self.jLabel3)
                    .addComponent(self.jTextFieldRegex, GroupLayout.PREFERRED_SIZE, 24, GroupLayout.PREFERRED_SIZE))
                .addGap(18, 18, 18)
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.TRAILING)
                    .addComponent(self.jButtonCancel, GroupLayout.PREFERRED_SIZE, 27, GroupLayout.PREFERRED_SIZE)
                    .addComponent(self.jButtonOK, GroupLayout.PREFERRED_SIZE, 27, GroupLayout.PREFERRED_SIZE))
                .addContainerGap(GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        )

    def addRegex(self, event):
        lastIndex = self.jTableRegex.getValueAt(self.jTableRegex.getRowCount()-1, 0)
        self.jTableRegex.addRow([lastIndex + 1, self.jTextFieldRuleName.getText(), self.jTextFieldRegex.getText()])
        print(self.jTableRegex.getModel().getDataVector())
        self.dispose()

    def closeRegexerGUIEdit(self, event):
        self.dispose()


class RegexTableModel(DefaultTableModel):

    def __init__(self, data, columnNames):
        DefaultTableModel.__init__(self, data, columnNames)

    def isCellEditable(self, row, column):
        canEdit = [False, False, False]
        return canEdit[column]

    def getColumnClass(self, column):
        columnClasses = [Integer, String, String]
        return columnClasses[column]


class RegexTableMouseListener(MouseListener):

    def getClickedIndex(self, event):
        eventTable = event.getSource()
        row = eventTable.getSelectedRow()
        return eventTable.getValueAt(row, 0)

    def getClickedRow(self, event):
        eventTable = event.getSource()
        return eventTable.getModel().getDataVector().elementAt(eventTable.getSelectedRow())

    def mouseClicked(self, event):
        if event.getClickCount() == 1:
            print("Single-click: {}".format(self.getClickedRow(event)))
        elif event.getClickCount() == 2:
            print("Double-click: {}".format(self.getClickedRow(event)))
            tbl = event.getSource()
            tbl.addRow([11, "dblclick-name", "dblclick-severity"])
        else:
            print("Another element: {}".format(event))

    def mouseEntered(self, event):
        pass

    def mouseExited(self, event):
        pass

    def mousePressed(self, event):
        pass

    def mouseReleased(self, event):
        pass


class RegexTable(JTable):

    def __init__(self, data, columnNames):
        model = RegexTableModel(data, columnNames)
        self.setModel(model)
        self.setAutoCreateRowSorter(True)
        self.getTableHeader().setReorderingAllowed(False)
        self.addMouseListener(RegexTableMouseListener())

    def addRow(self, data):
        self.getModel().addRow(data)

    def removeRow(self, row):
        self.getModel().removeRow(row)


# support for burp-exceptions
try:
    FixBurpExceptions()
except:
    pass