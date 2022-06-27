"""
Protobuf Finder
 > IDA plugin for reconstructing original .proto files from binary
"""

import re

# require google's protobuf library
from google.protobuf.descriptor_pb2 import FileDescriptorProto, FieldDescriptorProto
from google.protobuf.message import DecodeError

# IDA API imports
import idaapi
import ida_bytes
import ida_ida
import ida_kernwin


# Max protobuf size - used to load code from IDA database; 
MAX_PROTOBUF_SIZE = 0x100000

# Icon
icon = b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x000\x00\x00\x00%\x08\x06\x00\x00\x00\x04\x19j\xaf\x00\x00\x00\x01sRGB\x00\xae\xce\x1c\xe9\x00\x00\x00\x04gAMA\x00\x00\xb1\x8f\x0b\xfca\x05\x00\x00\x00\tpHYs\x00\x00\x0e\xc3\x00\x00\x0e\xc3\x01\xc7o\xa8d\x00\x00\x06\x0cIDATXG\xed\x97{PTu\x14\xc7\xcf\xdd]vY\x9e\xbb\x08\x08\xb8\x12h>\x92t@\x13\x07\xb2\x04\x93\xac\x1c\tL\x19\x9f\x199\x16\x16\x1a\x98\xa3i9\x84J\xa33\x068\xcd\xa0\xd9\x03m0Lj4\x07\xa3\xc9\x07\xa4#\xf8\xd8\x89-5\x1b\x9f\xa4;$\x12\xb2\xbca\x1f\xf7\xf6\xfb\xdd=\xbb\xee\xb2w/\xeb\x8c\x7f\xf4\xc7~\x98\xe3\xfd}\xcf]\x99s\xf8\x9d\xf3\xfb\x9d\x05/^\xbcx\xd1\x10+&v\x97\x18\xe7`\xf5\xc4\x0e\x11[@\xec\x7f\t\r\x9c\x06\xe8\x18\xb4;\xa3\x9f\xa3\x9f\x7f\xec0\xf8\xf4\x98\xbb\xebr\x17W^\xb9\x9a\xb8\xbe\xe6\xe4{\xe8\xf2\x98\xc9k2v\x8dz%\xa9\x89\x05\x0b\xaf\x1f\xf4wv\x87\xfa\xaa\x03\xa8\xee6\xf7\x0f<\x19\x1ce({.\xa7\x92\x7f\xe9!\x8f\x94\x80~c^^C]]\xc9\x82\x06\x1dz\xac\xbc<<\x04\xb2\xa3#!\xd2W\x0e\xe1\xea\x90\xf6\xf0\xf9\x0b\xa7\xa8__\xf9\x0cyE\xcb\xc7\xa9\x84\x026\xcd\x02\xe9\xe8PT\xce0\xe4gz\xd8\x84\xcc\xea\xf4\xcdG\xd05$\x1e\'\xa0/)\x8a\xef\xff\xa5\xa6v\xfa\xa9\x0b\xaa{\x03F\xde\x17\xa1\x90CUb\x1c\xff\xa4H\xfc\x03\xa0S\xa1\xccL8T\xed\x18@\x121{\tI\xd4~\x10\xb83\x9d.\x05\x912\x12CV\xec\xd4\x84=\xa9\xf9M\xe8\x12E\x82OQn\x97\x14\xa8\x06\xce5|\xf5\x93\xbe\xc5\x1e<\xc51x\x8a1X\xb5sP\xf0\x94\x06b4\t\x1e\xb6\xbd\x17LZ\xda\xef\xc2X8Vu\xb6\xe5F-\xca!\xf1(\x01\xd0\xea\n\xd9\xb6\xd6\xc95\xf7\xdb\xd0\x01\xb0i\xec\x13N\xc1K\xa2c\xb4\x11\xd9\xb9E(\x07\xa3\'\x96e]\x02\x98\xab\xafv\xe1R\x90;=m1s\x8fm9\x80R\x94!\x13\xd8\xf1\xf5\xad\\CG\xcf\x1a\x96\x9c%5-\x0f\xd0\x0b\xa4\xe6#p\x05`\xf2\x0b0\x04\xcdxa\x89:5\xd5\x80.!\xe8N\xf0\x18\xf5\xed]a\x8a\xc0n\x94\x82\x9ci\xb9\xba\xf8\xc5\xa3\x1fe\xa0t\x8bh\x02{k\xbb\xe3O\xb5\x86o\xdd3~\x13\x18X\x16\xbd\xce0r\x85\xd1\x1c\xa4\xca\x0e[\xfe\xd65t\xb9\x83\xee\x82\x15\x8e\x8b\xf2\xed\xe3\xe6\x92\':\\\xe1\xc8;\xed\xbf\xb7\xcasjw\xc7\xa0K\x10\xb7\t\x94\x1cnW\x9d\xbc\xc4\xec5\x99Au]\x9d\x08gF\xa6C\xb8C\xc9\xd8z\xc1<,\xb4lR\xc5\x0f\x1e\x9f\x1a6.\xaf\xfc\xb2n\x822r\x17JAh?\x9ch\xd6\x1dE)\x88\xdb\x04\xb4\xff\xf8\x14\xb4vqSQ\xc2\xcf\xe3\xf3!\xc8?\x18\x15@\xa3\xa1\x1b\x98(M\xfd\xf0\xb5\x9b\x0b\xd15\x14\xf9\xf8\xa4T\xd1\x7f\x1a\x96\x94\xe6\x8dT\x868\x9f\xc9\x83h\xed\xef\x98\xb8\xecD\xf1\xf7(]\x10L\xa0\xa0\xaa7\xaf\xad\x13\xf2P\xf2\xd0\x1eP\xa7mC\x05\xb0\xe6\xd2u\xa8\x92\x07mV\'$\x88\xd5\xbd\r\xdb\xb8a\x83O\x802\x11F\xbc\x14\xa5T\xa3\x12\xa6\xfa\xef\x8b\xaf\xa5W\x17\xceA\xe9\x84\xcb=\xb0\xa1\xb2/Fw\xc7\xd2HK\x07]N\\\xd8\x1e\x0b\xdd]\xad\xa8\xec\xa7\x8b\xbdA\x05\xa0\xc1\xd3\xf7\xb6Q\x82\xfe\x9f\x91\xd6\xa5\x95\x98\xcf\x96\xa6\xb4+\xcd\xb5b\xb7\x92\x8c\xdc\x0f\xeb\x9e\x9a\x9b\xb01i\x91\xd3\xfd\xe0\xba\x03\x0c\xf7\xaa\xbb\xe0)\xe3\x16\x1f\xc4\x15\x0f\rJhh\xa3~\xdb\x05F\x0f}[\xf0\x14\xfbqj\xa3iuE\xdd\xbc@\xf68JA\xcc\xa4\x1f\xaa\xee\x9eOAi\xc7%\x81\xf3\xe7Z\xf6+e\xd6YE\x88\xe0\xe8i\x90\xb8\xea$*;4x\xc7\xc1\x8e\x06M\x13\x1b<\x89\xd2\xec]v\x8b\xfb##\xe3\x8b\xf0\xba\xb4\x99\xb2\x16\xf4\xb8\xa2`d\x86\x85c\xa6\x9fEi\xc7%\x81\xba\xd2X\x83Zn\xcaD)H\x80f\x1a\xcc\xfc\xf0\xafN\x7f\xff\xa0c\xe8\xf2\x94\x85\xc4\x1c\x9b\x19\xb8\x9b\x1b\xa2\xb9\xae\xc6r\xce\xd8\x01\x9f\x87\\\x84\x11L\x1f\xbey\x88\\"\x03\xa9\x91]\xb1>a\xfeut\xd9\x11l\xe2\x8a\xfc\xd0#\xc3\x14\xfdn;\x9f\xc7O\x134{[s Y\xd1\x92\xa0M9\xf8/Kk\xbd\x84\x18\xadw{\xd3\x12h3\xf3Ip\\\xbb\n\xee\xed+c\xcc\xf7TRrB\xab\xa4&\xd8\xedw\xc1\xba\x87\x0e\xc8\x8c\\i\xf3\xdb\x07\xaaQ:\xe1\xb6m\xc8E"M+\xea\xd4\xb2\x8c4\x1e]\x82L\xd20\x85\xa5\xcb\xfd?F)\x06-)\xfbLDH\xe6\xb4S\xd2\xa1\xe7\xf2\x07\xa8y\x8c\xe4~.\xbe?\x16\xb6\xb3q\xbcVI\x94:\x06\xb8\xd4\xa6\xec}\x82\xa7\x9d\xe0\x0eP\x18\x86\xb1<;\x9a\xcdTH\xdd\xf7\x03\xe5J3W\x90[\xde\xe5\xd2\\\x02$\x13s\xdc\xa5\xfa\x06\xed\xcd\xf5\xb8\xb6#\x0f\x00x?\xe2\x1a<\xcf\xdc\x07_\xc6\xc70V\x15\x99\xed.x\x8a\xdb\x04(\x85\x8b\xd4M*\x85x?X\xc8\x84q\xbb\x959\xdcx\xbbO\xf4\xcaGh\xb9\xd9G\x8a\xe4\x1c\x83D\xdf\xea:N\xf8\xf8\x01\xec\xd7\xfc\x06\xe3\xc0\x94s<\xf3\x13\xd1\x8bN4\x01J%\xe9\x870\xdf~\xd1Q\xa1\xcf\x04\xaa-G,\xe5(\xc5\xd0ge\xcd\x99\x1d\xa6\x96\x0e\xa0\x86\xa4U&\x10JB\xed\'+=\xfd\xe6\xc1\xefP\xbae\xc8\x04(\x07\xd7\x0e[*\x03\x8b\xe8_\xa2\xa3\x17R\x96\xef\xeeu:a\x84\xa8\xcc\xbf1\xef\xc7"\xa9\x02%\x1f<M\xc2\tY\xb0\x0e\xfc5\x1e\x8d(\x1e%@\xfa\xa1\'i\x14\x9b\xe9\xc3\x88\xf7C\xb3\x81-&7\xb9\xdb~\xe0\xfe\\\x91!a\r[\x93\xe2\x18\xa8/\xf3A\xaf5\x89\xe4w0\tR\xf7\x10<+\x9bI\xd0y2\xa2x\x96\x00\x85\xf6C\x80\xb4\x7f\xc8~\xb8\xa2\xb7\x1c\xfe]\xcf9\xde\xbc<\x9c6%\x14:N\x97\x83\xd9\x1aWR\x9c\x04\x0e\x15>L\xe2\xd3w\xa5$xr\x96\xcaG\xacf\x9e\xfeVt\xb7\x1dy\xa4/\xf5\x94\x8c-\xfa7dJ\x19?j\xd8\xb2\xb7}S\xb0\xe9\xd8\x08\x85n\xc72u\x1dJ\x1e\xee\xec\x98x\x90\xca\x1cv\x87~\x9a\x85\xa5\x05\xcd3*\n5\xbf\xf2\xbf\xc5\'\xd8\x00\x93\x1b\xbe!;.\xfc\xe5\xc3\x8b\x17/^\xbc<^\x00\xfe\x03t\xd3\x12d\xcd*\xb7\xe1\x00\x00\x00\x00IEND\xaeB`\x82'
icon_id = idaapi.load_custom_icon(data=icon, format="png")

class util:
    def syntax_highlight_proto(line):
        colored_line = line
        # Strings
        str = re.search("\".*\"",colored_line)
        if str:
            colored_line = colored_line[:str.start()] + idaapi.COLSTR(colored_line[str.start():str.end()], idaapi.SCOLOR_DSTR) + colored_line[str.end():]
        # Variables
        var = re.search("\w+\s*(?==)",colored_line)
        if var:
            colored_line = colored_line[:var.start()] + idaapi.COLSTR(colored_line[var.start():var.end()], idaapi.SCOLOR_CODNAME) + colored_line[var.end():]
        # Objects
        obj = re.search("\w+\s*(?={)",colored_line)
        if obj:
            colored_line = colored_line[:obj.start()] + idaapi.COLSTR(colored_line[obj.start():obj.end()], idaapi.SCOLOR_IMPNAME) + colored_line[obj.end():]
        # Numbers
        num = re.search("\W\d+\W",colored_line)
        if num:
            colored_line = colored_line[:num.start()] + idaapi.COLSTR(colored_line[num.start():num.end()], idaapi.SCOLOR_DNUM) + colored_line[num.end():]

        return colored_line


# IDA plugin Action Handler
class ProtobufFinder(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    # Called when the Search -> Protobuf Finder is clicked
    def activate(self, ctx):
        print("[Protobuf] Search started.")
        runProtod() # run search
        print("[Protobuf] Search done.")
        pass

    # This action is always available.
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


class protobuf_fetch_t(idaapi.plugin_t):
    comment = "Protobuf string finder."
    help = "A plugin to find a parse embedded proto files in binaries with basic syntax highlight."
    wanted_name = "Protobuf"
    wanted_hotkey = ""
    flags = idaapi.PLUGIN_KEEP

    def init(self):
        self.printBanner()

        protobuf_desc = idaapi.action_desc_t(
            'protobuf:search',      # The action name. This acts like an ID and must be unique
            'Protobuf Finder',      # The action text.
             ProtobufFinder(),      # The action handler.
            '',                     # Optional: the action shortcut
            '',                      # Optional: the action tooltip (available in menus/toolbar)
            icon_id)                      # Optional: the action icon (shows when in menus/toolbars)
        idaapi.register_action(protobuf_desc)

        # Insert the action in the menu
        if not idaapi.attach_action_to_menu("Search", "protobuf:search", idaapi.SETMENU_APP):
            print("[Protobuf] Failed attaching to menu.")

        return idaapi.PLUGIN_KEEP
      
    def run(self):
        pass

    def term(self):
        pass

    def printBanner(self):
        print("---------------------------------------------------------------------------------------------")
        print("Protobuf string finder loaded.")
        print("Run via Search -> Protobuf Finder")
        print("---------------------------------------------------------------------------------------------")


def runProtod():
    extractor = ProtobufExtractor()
    extractor.extract()


def PLUGIN_ENTRY():
    return protobuf_fetch_t()


# =======================================================================================
# rewritten Protod code to Python3, using IDA API
# =======================================================================================

###########
# helpers
###########

def is_valid_filename(filename):
    '''
    Check if given filename may be valid
    '''
    charset = 'abcdefghijklmnopqrstuvwxyz0123456789-_/$,.[]()'
    for char in filename.lower():
        if chr(char) not in charset:
            return False
    return True


def decode_varint128(stream):
    '''
    Decode Varint128 from buffer
    '''
    bits = ''
    count = 0
    for stream_byte in stream:
        count += 1
        raw_byte = stream_byte
        bits += (bin((raw_byte&0x7F))[2:]).rjust(7,'0')
        if (raw_byte&0x80) != 0x80:
            break
    return (int(bits, 2), count)


def render_type(field_type, package):
    '''
    Return the string representing a given type inside a given package
    '''
    i = 0
    nodes = field_type.split('.')
    nodes_ = package.split('.')
    for i in range(len(nodes)):
        if i < len(nodes_):
            if nodes[i] != nodes_[i]:
                return '.'.join(nodes[i:])
        else:
            return '.'.join(nodes[i:])
    return '.'.join(nodes[i:])


#############################
# Protobuf fields walker
#############################

class ProtobufFieldsWalker:
    '''
    Homemade Protobuf fields walker

    This class allows Protod to walk the fields
    and determine the probable size of the protobuf
    serialized file.
    '''

    def __init__(self, stream):
        self._stream = stream
        self._size =  -1

    def get_size(self):
        return self._size

    def walk(self):
        end = False
        offset = 0
        while (not end) and (offset<len(self._stream)):
            # read tag
            tag = self._stream[offset]
            offset += 1
            wire_type = tag&0x7
            if wire_type == 0:
                value, size = decode_varint128(self._stream[offset:])
                offset += size
            elif wire_type == 1:
                offset += 8
            elif wire_type == 2:
                value, size = decode_varint128(self._stream[offset:])
                offset += size + value
            elif wire_type == 5:
                offset += 4
            elif wire_type == 3:
                continue
            elif wire_type == 4:
                continue
            else:
                end = True
        self._size = offset-1


#############################
# Serialized metadata parsing
#############################

class FileDescriptorDisassembler:
    '''
    Core disassembling class

    This class parses the provided serialized data and
    produces one or many .proto files.
    '''

    def __init__(self, file_desc):
        self.desc = file_desc

    def getLabel(self, l):
        return [None, 'optional', 'required', 'repeated'][l]

    def getTypeStr(self, t):
        types = [
            None,
            'double',
            'float',
            'int64',
            'uint64',
            'int32',
            'fixed64',
            'fixed32',
            'bool',
            'string',
            'group',
            'message',
            'bytes',
            'uint32',
            'enum',
            'sfixed32',
            'sfixed64',
            'sint32',
            'sint64'
        ]
        return types[t]

    def renderEnum(self, enum, depth=0, package='', nested=False):
        buffer = '\n'
        buffer += '%senum %s {\n' % (' '*depth, enum.name)
        for value in enum.value:
            buffer += '%s%s = %d;\n' % (' '*(depth+1), value.name, value.number)
        buffer += '%s}' % (' '*depth)
        buffer += '\n'
        return buffer

    def renderField(self, field, depth=0, package='', nested=False):
        buffer = ''
        try:
            if field.HasField('type'):
                # message case
                if field.type == FieldDescriptorProto.TYPE_MESSAGE or field.type == FieldDescriptorProto.TYPE_ENUM:
                    field.type_name = render_type(field.type_name[1:], package)
                    buffer += '%s%s %s %s = %d;\n' % (' '*depth, self.getLabel(field.label), field.type_name, field.name, field.number)
                else:
                    if field.HasField('default_value'):
                        if self.getTypeStr(field.type) == 'string':
                            field.default_value = '"%s"'% field.default_value
                        buffer += '%s%s %s %s = %d [default = %s];\n' % (' '*depth, self.getLabel(field.label), self.getTypeStr(field.type), field.name, field.number, field.default_value)
                    else:
                        buffer += '%s%s %s %s = %d;\n' % (' '*depth, self.getLabel(field.label), self.getTypeStr(field.type), field.name, field.number)
        except ValueError:
            buffer += '%smessage %s {\n' % (' '*depth, field.name)
            _package = package+'.'+field.name

            if len(field.nested_type)>0:
                for nested in field.nested_type:
                    buffer += self.renderField(nested, depth+1, _package, nested=True)
            if len(field.enum_type)>0:
                for enum in field.enum_type:
                    buffer += self.renderEnum(enum, depth+1, _package)
            if len(field.field)>0:
                for field in field.field:
                    buffer += self.renderField(field, depth+1, _package)
            buffer += '%s}' % (' '*depth)
            buffer += '\n\n'
        return buffer


    def render(self, filename=None):
        print('[Protobuf][+] Processing %s' % self.desc.name)
        buffer = ''
        buffer += 'package %s;\n\n' % self.desc.package

        # add dependencies
        if len(self.desc.dependency)>0:
            for dependency in self.desc.dependency:
                buffer += 'import "%s";\n' % dependency
            buffer += '\n'

        if len(self.desc.enum_type)>0:
            for enum in self.desc.enum_type:
                buffer += self.renderEnum(enum, package=self.desc.package)
        if len(self.desc.message_type)>0:
            for message in self.desc.message_type:
                buffer += self.renderField(message, package=self.desc.package)
        
        # print result into IDA window
        textWindow = ida_kernwin.simplecustviewer_t()
        if textWindow.Create("Protobuf file: " + self.desc.name):
            for line in buffer.split('\n'):
                textWindow.AddLine(util.syntax_highlight_proto(line))
            textWindow.Show()
        else:
            print ("[Protobuf] Failed to open window - it is probably already open.")


#############################
# Main code
#############################

class ProtobufExtractor:
    def __init__(self):
        pass

    def extract(self):
        protos = []
        searchStartAddr = 0
        
        while True:
            # search binary for ".proto" string
            r = ida_bytes.bin_search(searchStartAddr,ida_ida.MAXADDR,bytes([0x2E, 0x70, 0x72, 0x6F, 0x74,0x6F]),bytes([0xFF,0xFF,0xFF,0xFF,0xFF,0xFF]),1,1)
            if r == idaapi.BADADDR:
                print("[Protobuf][dbg] Search results into BADADDR (not found). Break!")
                break

            searchStartAddr = r+1
            print(f"[Protobuf][dbg] String \".proto\" found at {hex(r)}.")
            
            # Find beginning of the whole proto string
            for j in range(64):
                try:
                    protostring = ida_bytes.get_bytes(r-j-1, MAX_PROTOBUF_SIZE, False)
                    
                    if decode_varint128(protostring[1:])[0]==(j+5) and is_valid_filename(protostring[1+1:j+6+1]):
                        print(f"[Protobuf][dbg] Protostring identified: {protostring[:40]} [...]")
                       
                        # Walk the fields and get a probable size
                        walker = ProtobufFieldsWalker(protostring)
                        walker.walk()
                        probable_size = walker.get_size()
                       
                        print(f"[Protobuf][dbg] Protostring section size {hex(probable_size)}.")
                       
                        """
                        Probable size approach is not perfect,
                        we add a delta of 1024 bytes to be sure
                        not to miss something =)
                        """
                        for k in range(probable_size+1024, 0, -1):
                            try:
                                fds = FileDescriptorProto()
                                fds.ParseFromString(protostring[:k])
                                protos.append(protostring[:k])
                                print('[Protobuf][dbg][i] Found protofile %s (%d bytes)' % (protostring[:j+5], k))
                                break
                            except DecodeError:
                                pass
                            except UnicodeDecodeError:
                                pass
                        break
                except IndexError:
                    pass
        if protos:
            # Load successively each binary proto file and rebuild it from scratch
            seen = []
            for content in protos:
                try:
                    # Load the prototype
                    fds  = FileDescriptorProto()
                    fds.ParseFromString(content)
                    res = FileDescriptorDisassembler(fds)
                    if len(res.desc.name)>0:
                        if res.desc.name not in seen:
                            res.render() # disassemble and show .proto file in IDA window
                            seen.append(res.desc.name)
                except DecodeError:
                    pass
        else:
            ida_kernwin.info("No embedded proto files were discovered.")
