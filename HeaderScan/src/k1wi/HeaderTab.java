package k1wi;

import burp.BurpExtender;
import java.awt.Component;
import java.awt.FlowLayout;
import java.awt.Panel;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import javax.swing.JButton;
import javax.swing.JPanel;
import javax.swing.JLabel;
import javax.swing.JRadioButton;
import burp.ITab;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JCheckBox;


public class HeaderTab implements ITab,ActionListener {
    	private BurpExtender engine;
	                
        private JLabel a = new javax.swing.JLabel("HeaderScan config");
        private JLabel b = new javax.swing.JLabel("Automatically scan requests as you browse:");
	private JCheckBox c = new JCheckBox("Enabled");
                
        public HeaderTab(BurpExtender listener){
		this.engine = listener;
	}
        
	@Override
	public String getTabCaption() {
		return "HeaderScan";
	}
	@Override
	public Component getUiComponent() {
		JPanel main = new JPanel();
                BoxLayout boxLayout1 = new BoxLayout(main, BoxLayout.Y_AXIS);
                main.setLayout(boxLayout1);
                main.setLayout(new FlowLayout());
		c.addActionListener(this);
                c.setSelected(this.engine.getstate());
                main.add(Box.createVerticalGlue());
                main.add(c);
		return main;
	}
        
        public void actionPerformed(ActionEvent e) {
                    if(this.c.isSelected())
                        this.engine.enable();
                    else
                        this.engine.disable();
			}

}