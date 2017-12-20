require 'java'
java_import 'burp.IExtensionHelpers'

java_import 'javax.swing.JOptionPane'
java_import 'burp.ITab'
java_import 'javax.swing.JPanel'
class AbtractBrupExtensionUI < JPanel
  include ITab

  def initialize(extension)
    @extension = extension
    super()
    self.setLayout nil
  end

  def extensionName
    @extension.extensionName
  end

  alias_method :getTabCaption, :extensionName

  def getUiComponent
    self
  end
end

java_import('java.awt.Insets')
class AbstractBurpUIElement
  def initialize(parent, obj, positionX, positionY, width, height)
    @swingElement = obj
    setPosition parent, positionX, positionY, width, height
    parent.add @swingElement
  end

  def method_missing(method, *args, &block)
    @swingElement.send(method, *args)
  end

  private
  def setPosition(parent, x,y,width,height)
    insets = parent.getInsets
    size = @swingElement.getPreferredSize()
    w = (width > size.width) ? width : size.width
    h = (height > size.height) ? height : size.height
    @swingElement.setBounds(x + insets.left, y + insets.top, w, h)
  end
end

java_import 'javax.swing.JLabel'
class BLabel < AbstractBurpUIElement
  def initialize(parent, positionX, positionY, width, height, caption, align= :left)
    case align
      when :left
        a = 2
      when :right
        a = 4
      when :center
        a = 0
      else
        a = 2 #align left
    end
    super parent, JLabel.new(caption, a),positionX, positionY, width, height
  end
end

java_import 'javax.swing.JButton'
class BButton < AbstractBurpUIElement
  def initialize(parent, positionX, positionY, width, height, caption, &onClick)
    super parent, JButton.new(caption), positionX, positionY, width, height
    @swingElement.add_action_listener onClick
  end
end

java_import 'javax.swing.JSeparator'
class BHorizSeparator < AbstractBurpUIElement
  def initialize(parent, positionX, positionY, width)
    super parent, JSeparator.new(0), positionX, positionY, width, 1
  end
end

class BVertSeparator < AbstractBurpUIElement
  def initialize(parent, positionX, positionY, width)
    super parent, JSeparator.new(0), positionX, positionY, width, 1
  end
end

java_import 'javax.swing.JCheckBox'
class BCheckBox < AbstractBurpUIElement
  def initialize(parent, positionX, positionY, width, height, caption)
    super parent, JCheckBox.new(caption), positionX, positionY, width, height
  end
end

#########################################################################################
#Begin Burp Extension
#########################################################################################
class ExtensionUI < AbtractBrupExtensionUI
  attr_accessor :value
  attr_accessor :factoryCommandMulti
  attr_accessor :factoryCommandSingle

  def buildUI
    BHorizSeparator.new self, 0, 7, 250
    BLabel.new self, 250, 2, 300, 0, 'Payload Processor', :center
    BHorizSeparator.new self, 550, 17, 250
    BLabel.new self,2, 22, 0,0,  'Your payload is provided to the command on STDIN, and value written to STDOUT is substituted into the request.'
    BLabel.new self,2, 34, 0,0,  'This is thread safe if your command otherwise is, but may create a large number of process if threads are used.'
    BButton.new( self, 2, 50, 0,0, 'Change Command') { |evt| valueButtonOnClick }
    BLabel.new self, 2,74,0,0, 'Current Command:'
    @txtlabel = BLabel.new self, 2,92,620,0,'cat'

    BHorizSeparator.new self, 0, 110, 250
    BLabel.new self, 250, 102, 300, 0, 'Payload Generator (Multi)', :center
    BHorizSeparator.new self, 550, 110, 250
    BLabel.new self, 2, 119, 0, 0, 'STDOUT of your command is used to generate payloads'
    BButton.new(self, 2, 134, 0,0, 'Change Command') {|evt| generatorMOnClick}
    @exit_mode_cbx = BCheckBox.new( self, 2, 156, 0, 0, 'Stop on zero exit status (checked), nonzero status (unchecked)')
    @txtMultiCommand = BLabel.new(self, 2, 172, 620, 0, "'echo 'HiThere'")

    BHorizSeparator.new self, 0, 210, 250
    BLabel.new self, 250, 202, 300, 0, 'Payload Generator (Single)', :center
    BHorizSeparator.new self, 550, 210, 250
    BLabel.new self, 2, 219, 0, 0, 'STDOUT of your command is used to generate payloads, each line is one payload'
    BButton.new(self, 2, 234, 0,0, 'Change Command') {|evt| generatorSOnClick}
    @txtSingleCommand = BLabel.new(self, 2, 272, 620, 0, "echo 'HiThere'")
  end


  def valueButtonOnClick
    @extension.value = JOptionPane.showInputDialog(@mainPanel, "Enter command string!")
    @txtlabel.setText @extension.value
  end

  def generatorMOnClick
    @factoryCommandMulti.command = JOptionPane.showInputDialog(@mainPanel, "Enter command string!")
    @txtMultiCommand.setText @factoryCommandMulti.command
    @factoryCommandMulti.exit_on = @exit_mode_cbx.isSelected ? :success : :error
  end

  def generatorSOnClick
    @factoryCommandSingle.command = JOptionPane.showInputDialog(@mainPanel, "Enter command string!")
    @txtSingleCommand.setText @factoryCommandSingle.command
  end

end

require 'open3'
require 'shellwords'
java_import 'burp.IIntruderPayloadProcessor'
class CommandPayloadProcessor
  include IIntruderPayloadProcessor
  include IExtensionHelpers
  attr_accessor :value
  attr_accessor :extensionName

  def bytesToString(java_bytes)
    rb = Array.new
    java_bytes.each { |b| rb << b }
    rb.pack('C*')
  end

  def to_utf8(str)
    begin
      ret = str.encode("UTF-8")
    rescue Encoding::UndefinedConversionError
      ret = str.force_encoding('ISO-8859-1').encode("UTF-8")
    end
    ret
  end

  def initialize(name=nil, value='cat')
    @value = value
    @extensionName = name.to_s
  end

  alias_method :getProcessorName, :extensionName

  def processPayload(currentPayload, originalPayload, baseValue)
    payload = to_utf8(bytesToString(currentPayload))
    out, tr = Open3.capture2(@value, :stdin_data=>payload)    
    bytes = out.bytes
    bytes
  rescue => e
    puts e.message
  end

end

java_import 'burp.IIntruderAttack'
java_import 'burp.IIntruderPayloadGenerator'
class GeneratorMulti
  include IIntruderPayloadGenerator
  attr_accessor :exit_on
  attr_accessor :command

  def initialize
    @exit_on = :success
    @last_status = nil
    @command = "echo 'Hi There!'"
  end

  def hasMorePayloads
    return true unless @last_status
    return false if ((@last_status.exitstatus == 0) and (@exit_on == :success))
    return false if ((@last_status.exitstatus != 0) and (@exit_on == :error))
    true
  end

  def getNextPayload(baseValue)
    stdout_str, @last_status = Open3.capture2(@command)
    stdout_str.bytes
  end

  def reset
    @last_status = nil
  end
end

class GeneratorSingle
  include IIntruderPayloadGenerator
  attr_accessor :command

  def initialize
    @command = "echo 'Hi There!'"
    @command_out = nil
    @execute_status = false
  end

  def hasMorePayloads
    return false if @hasError
    return true if !(@execute_status)
    return !(@command_out.eof?)
  end

  def getNextPayload(baseValue)
    reset unless @execute_status
    return @command_out.readline.chop.bytes if @command_out
    return [0]
  end

  def reset
    puts @command
    @command_out = IO.popen(@command)
    @execute_status = true
  rescue
    @hasError = true
  end
end

java_import 'burp.IIntruderPayloadGeneratorFactory'
class FactoryCommandMulti
  include IIntruderPayloadGeneratorFactory
  attr_accessor :command
  attr_accessor :exit_on

  def getGeneratorName
    'Command (Multi)'
  end

  def createNewInstance(attack)
    bgp = GeneratorMulti.new
    bgp.command = @command
    bgp.exit_on = @exit_on
    bgp
  end
end

class FactoryCommandSingle
  include IIntruderPayloadGeneratorFactory
  attr_accessor :command

  def getGeneratorName
    'Command (Single)'
  end

  def createNewInstance(attack)
    bgp = GeneratorSingle.new
    bgp.command = @command
    bgp
  end
end

java_import 'burp.IBurpExtender'
class BurpExtender
  include IBurpExtender

  ExtensionName = 'Command'

  def initialize
    @payloadProcessor = CommandPayloadProcessor.new ExtensionName, 'cat'
    @extensionInterface = ExtensionUI.new @payloadProcessor
    @extensionInterface.factoryCommandMulti = FactoryCommandMulti.new
    @extensionInterface.factoryCommandSingle = FactoryCommandSingle.new
    @extensionInterface.buildUI
  end

  def registerExtenderCallbacks(callbacks)
    callbacks.setExtensionName ExtensionName
    callbacks.registerIntruderPayloadProcessor @payloadProcessor
    callbacks.addSuiteTab @extensionInterface

    callbacks.registerIntruderPayloadGeneratorFactory @extensionInterface.factoryCommandMulti
    callbacks.registerIntruderPayloadGeneratorFactory @extensionInterface.factoryCommandSingle
  end

end
