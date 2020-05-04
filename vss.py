#!/usr/bin/python

import argparse
import sys

__version__ = '1.0'
__date__ = '2020-04-27'

class Range(argparse.Action):
    def __init__(self, min=None, max=None, *args, **kwargs):
        self.min = min
        self.max = max
        super(Range, self).__init__(*args, **kwargs)

    def __call__(self, parser, namespace, value, option_string=None):
        for val in value:
            if not (self.min <= val <= self.max):
                msg = 'invalid choice: %r (choose from %d to %d)' % (val, self.min, self.max)
                raise argparse.ArgumentError(self, msg)
        setattr(namespace, self.dest, value)


class FileTypeWithExtensionCheck(argparse.FileType):
    def __init__(self, mode='r', valid_extensions=None, **kwargs):
        super(FileTypeWithExtensionCheck, self).__init__(mode, **kwargs)
        self.valid_extensions = valid_extensions

    def __call__(self, string):
        if self.valid_extensions:
            if not string.endswith(self.valid_extensions):
                msg = 'invalid file extension: choose from: %s' % repr(self.valid_extensions)
                raise argparse.ArgumentTypeError(msg)
        return super(FileTypeWithExtensionCheck, self).__call__(string)


class ArgumentAchiever():
    def __init__(self, validExtensions, minValue, maxValue, generationValues):
        self.validExtensions = validExtensions
        self.minValue = minValue
        self.maxValue = maxValue
        self.genValues = generationValues
        self.parser = None

    def __call__(self):
        self.parser = argparse.ArgumentParser(prog='vss', description = 'Add or remove one or more encryption classes from the static session or get information about this session', add_help=False, usage='%(prog)s (infile) -a N [N ...] -g {{{0}}} \n       %(prog)s (infile) -r N [N ...] -g {{{0}}} \n       %(prog)s (infile) -i \n       %(prog)s (infile) -ii'.format(','.join(map(str,self.genValues))), epilog='Author: pawel.lucjan@orange.com')
        self.addInputFile()
        self.addActionGroup()
        self.addOtherGroup()
        return self.parser.parse_args()

    def addInputFile(self):
        self.parser.add_argument('infile', type=FileTypeWithExtensionCheck('r', valid_extensions=self.validExtensions), help = 'static session file ({0})'.format(repr(self.validExtensions)[1:-1]))
        
    def addActionGroup(self):
        action_group = self.parser.add_mutually_exclusive_group(required=True)
        action_group.add_argument('-a', '--add', help='one or more decimal numbers (between %(min)s and %(max)s) of encryption classes to add to the file', nargs='+', type=int, action=Range, min=self.minValue, max=self.maxValue, metavar='N', default=False)
        action_group.add_argument('-r', '--remove', help='one or more decimal numbers (between %(min)s and %(max)s) of encryption classes to remove from the file', nargs='+', type=int, action=Range, min=self.minValue, max=self.maxValue, metavar='N', default=False)
        action_group.add_argument('-i', '--info', help='information about the static session (two modes depends on the number of occurrences)', action='count')

    def addOtherGroup(self):
        other_group = self.parser.add_argument_group('others')
        other_group.add_argument('-g', '--gen', help='generation of encryption classes', type=int, choices=self.genValues, required='-a' in sys.argv or '-r' in sys.argv)
        other_group.add_argument('-h', '--help', action='help', default=argparse.SUPPRESS, help='show this help message and exit')
        other_group.add_argument('--version', action='version', version='VSS {0} [{1}]'.format(__version__, __date__))


class StaticFile():
    def __init__(self, inputArgs):
        self.inFile = inputArgs.infile
        self.hexContent = self.inFile.read().encode("hex")
        self.gen = inputArgs.gen
        self.info = inputArgs.info
        self.toAdd = inputArgs.add
        self.toRemove = inputArgs.remove
        self.genIndexes = {}
        self.genEncryptions = {}
        self.otherInfo = {}
        self.genOptions = {0: 'Cardless', 2: 'PC2.6', 3: 'PC3.0', 5: 'PC5.0'}

    def takeAction(self):
        self.setVariables()
        if self.toAdd:
            self.addEncryption()
            self.saveToFile()
        elif self.toRemove:
            self.removeEncryption()
            self.saveToFile()
        elif self.info:
            self.printInfo()

    def setVariables(self):
        self.setNameAndCASID()
        if self.hexContent:
            offset = 4
            fileLen = offset + 2*int(self.hexContent[0:2], 16)
            idx = offset;
            while idx < fileLen:
                tagVal = self.hexContent[idx:idx+2]
                tagLen = int(self.hexContent[idx+2:idx+4], 16)
                if tagVal in ['10', '13', '14']:
                    idx = self.set_XID_CI_SOID(idx, offset, tagLen, tagVal)
                elif tagVal in ['17']:
                    idxTagStart = idx
                    idxTagEnd = idx + offset + 2*tagLen
                    idx += offset
                    tagEncVal = self.hexContent[idx:idx+2]
                    idx, gnr = self.getGeneration(idx, offset, tagEncVal)
                    idx = self.setEnc(idx, offset, idxTagEnd, gnr)
                    self.genIndexes[gnr] = [idxTagStart, idxTagEnd]
                else:
                    break
        else:
            print 'This input file is empty'
    
    def setNameAndCASID(self):
        fileName = self.inFile.name.split('/')[-1]
        self.otherInfo['Session'] = fileName.split('.')[1]
        self.otherInfo['CAS_ID'] = fileName.split('.')[0]

    def set_XID_CI_SOID(self, idx, offset, tagLen, tagVal):
        idx += offset + 2*tagLen
        if tagVal in ['10']:
            self.otherInfo['XID'] = '0x{0}'.format(self.hexContent[idx-2*tagLen:idx])
        elif tagVal in ['13']:
            self.otherInfo['CI'] = '0x{0}'.format(self.hexContent[idx-2*tagLen:idx])
        elif tagVal in ['14']:
            self.otherInfo['SOID'] = '0x{0}'.format(self.hexContent[idx-2*tagLen:idx])
        return idx

    def getGeneration(self, idx, offset, tagEncVal):
        if tagEncVal in ['e2', 'e0']:
            gnr = 0
            self.otherInfo['Key_Index'] = "N/A"
            self.otherInfo['ECM_Mode'] = "Classic"
            self.otherInfo['Generation'] = "ALL_CARD"
        elif tagEncVal in ['90']:
            tagEncLen = int(self.hexContent[idx+2:idx+4], 16)
            idx += offset + 2*tagEncLen
            if tagEncLen == 3:
                gnr = 2
                self.otherInfo['Key_Index'] = int(self.hexContent[idx-2:idx], 16)
                self.otherInfo['ECM_Mode'] = "Classic"
                self.otherInfo['Generation'] = "ALL_CARD"
            elif tagEncLen == 7:
                generacja = self.hexContent[idx-6:idx]
                if generacja == '0577ff':
                    gnr = 3
                elif generacja == '070cff':
                    gnr = 5
                self.otherInfo['Key_Index'] = int(self.hexContent[idx-8:idx-6], 16)
                self.otherInfo['ECM_Mode'] = "Multigeneration"
                if "Generation" not in self.otherInfo:
                    self.otherInfo['Generation'] = "PC{0}.0".format(gnr)
                else:
                    self.otherInfo['Generation'] += "/PC{0}.0".format(gnr)
        return idx, gnr
    
    def setEnc(self, idx, offset, idxTagEnd, gnr):
        while idx < idxTagEnd:
            tagEVal = self.hexContent[idx:idx+2]
            tagELen = int(self.hexContent[idx+2:idx+4], 16)
            idx += offset + 2*tagELen
            if tagEVal == 'e2':
                self.genEncryptions.setdefault(gnr, []).append(int(self.hexContent[idx-2:idx], 16))
            elif tagEVal == 'e0':
                self.setOthers(idx, tagELen, gnr)
        return idx

    def setOthers(self, idx, tagELen, gnr):
        content = self.hexContent[idx-2*tagELen:idx]
        pcKey = 'Other_{0}'.format(self.genOptions[gnr])
        if '2f' in content:
            self.otherInfo.setdefault(pcKey, []).extend(["Moral_Level", "Freescrambling"])
        elif '0f' in content:
            self.otherInfo.setdefault(pcKey, []).append("Moral_Level")
        elif '20' in content:
            self.otherInfo.setdefault(pcKey, []).append("Freescrambling")
        if '02' in content:
            self.otherInfo.setdefault(pcKey, []).append("Hardware_CWP")
        elif '01' in content:
            self.otherInfo.setdefault(pcKey, []).append("Software_CWP")
  
    def addEncryption(self):
        if self.gen in self.genIndexes:
            for encryption in self.toAdd:
                if self.gen not in self.genEncryptions or encryption not in self.genEncryptions[self.gen]:
                    newEncryption = 'e2030000{0:02x}'.format(encryption)
                    newTagLen = int(self.hexContent[self.genIndexes[self.gen][0]+2:self.genIndexes[self.gen][0]+4], 16) + len(newEncryption)/2
                    newFileLen = int(self.hexContent[:2], 16) + len(newEncryption)/2
                    self.hexContent = '{0:02x}'.format(newFileLen) + self.hexContent[2:self.genIndexes[self.gen][0]+2] + \
                    '{0:02x}'.format(newTagLen) + self.hexContent[self.genIndexes[self.gen][0]+4:self.genIndexes[self.gen][-1]] + \
                    newEncryption + self.hexContent[self.genIndexes[self.gen][-1]: ]
                    self.genIndexes[self.gen][-1] += len(newEncryption)
                    self.genEncryptions.setdefault(self.gen, []).append(encryption)
                    print 'Class {0} has been successfully added'.format(encryption)
                else:
                    print 'Class {0} already exists in this generation and cannot be added again!'.format(encryption)
        else:
            print 'There is no {0} generation in this static session'.format(self.genOptions[self.gen])

    def removeEncryption(self):
        if self.gen in self.genIndexes:
            for encryption in self.toRemove:
                if self.gen in self.genEncryptions and encryption in self.genEncryptions[self.gen]:
                    position = len(self.genEncryptions[self.gen]) - self.genEncryptions[self.gen].index(encryption)
                    encLen = 10
                    newTagLen = int(self.hexContent[self.genIndexes[self.gen][0]+2:self.genIndexes[self.gen][0]+4], 16) - encLen/2
                    newFileLen = int(self.hexContent[:2], 16) - encLen/2
                    self.hexContent = '{0:02x}'.format(newFileLen) + self.hexContent[2:self.genIndexes[self.gen][0]+2] + \
                    '{0:02x}'.format(newTagLen) + self.hexContent[self.genIndexes[self.gen][0]+4:self.genIndexes[self.gen][-1]-position*encLen] + \
                    self.hexContent[self.genIndexes[self.gen][-1]-(position-1)*encLen: ]
                    self.genIndexes[self.gen][-1] -= encLen
                    self.genEncryptions[self.gen].remove(encryption)
                    print 'Class {0} has been successfully removed'.format(encryption)
                else:
                    print 'Class {0} does not exist in this generation and cannot be removed!'.format(encryption)
        else:
                print 'There is no {0} generation in this static session'.format(self.genOptions[self.gen])

    def printInfo(self):
        keys = ['Session', 'CAS_ID', 'XID', 'CI', 'SOID', 'Key_Index', 'ECM_Mode', 'Generation', 'Other_PC2.6', 'Other_PC3.0', 'Other_PC5.0', 'Other_Cardless', 'Classes_PC2.6', 'Classes_PC3.0', 'Classes_PC5.0', 'Classes_Cardless']
        for gen in self.genEncryptions:
            self.otherInfo['Classes_{0}'.format(self.genOptions[gen])] = self.genEncryptions[gen]
        if self.info == 1:
            infos = []
            for key in keys[:-8]:
                infos.append(self.otherInfo[key] if key in self.otherInfo else '')
            for key in keys[-8:-4]:
                infos.append(','.join(map(str, self.otherInfo[key])) if key in self.otherInfo else '')
            for key in keys[-4:]:
                infos.append(','.join(map(str, sorted(self.otherInfo[key]))) if key in self.otherInfo else '')
            print ';'.join(keys)
            print ';'.join(map(str, infos))
        elif self.info > 1:
            for key in keys[:-8]:
                print "{0}: {1}".format(key, self.otherInfo[key] if key in self.otherInfo else '-')
            for key in keys[-8:-4]:
                print "{0}: {1}".format(key, ', '.join(map(str, self.otherInfo[key])) if key in self.otherInfo else '-')
            for key in keys[-4:]:
                print "{0}: {1}".format(key, ', '.join(map(str, sorted(self.otherInfo[key]))) if key in self.otherInfo else '-')

    def saveToFile(self):
        outFile = self.inFile.name[:-5] + '_VSS' + self.inFile.name[-5:]
        with open(outFile, 'w') as file:
            file.write(self.hexContent.decode("hex"))


vssArgs = ArgumentAchiever(validExtensions=('.stat'), minValue=1, maxValue=255, generationValues=[0,2,3,5])
inputArgs = vssArgs()
staticFile = StaticFile(inputArgs)
staticFile.takeAction()
