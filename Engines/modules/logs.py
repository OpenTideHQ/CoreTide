from typing import Literal, NamedTuple, List
from dataclasses import dataclass

import os
import re
import textwrap

class ANSI:
    """
    Utility class encapsulating data and behaviours to work with ANSI
    Formatting
    """

    @dataclass
    class Colors:
        """
        ANSI Escape code for Foreground (Text) Colors
        """
        PURPLE = "\033[95m"
        DARK_BLUE = "\033[34m"
        BLUE = "\033[94m"
        CYAN = "\033[96m"
        GREEN = "\033[92m"
        ORANGE = "\033[93m"
        RED = "\033[91m"

    @dataclass
    class Background:
        """
        ANSI Escape codes for Background Colors
        """
        PURPLE = "\033[105m"
        DARK_BLUE = "\033[44m"
        BLUE = "\033[104m"
        CYAN = "\033[106m"
        GREEN = "\033[102m"
        ORANGE = "\033[103m"
        RED = "\033[101m"

    @dataclass
    class Formatting:
        """
        ANSI Escapes code related to changing font display properties
        """
        BOLD = "\033[1m"
        UNDERLINE = "\033[4m"
        ITALICS = "\033[3m"
        STOP = "\033[0m"
        INVERSE = "\033[7m"

    class Inverse:
        """
        Allows to map a Colors.<color> to a Foreground.<color>, or vice versa
        """
        def __init__(self, color_code):
            foreground_background_mapping = {
                ANSI.Colors.PURPLE : ANSI.Background.PURPLE,
                ANSI.Colors.DARK_BLUE: ANSI.Background.DARK_BLUE,
                ANSI.Colors.BLUE : ANSI.Background.BLUE,
                ANSI.Colors.CYAN : ANSI.Background.CYAN,
                ANSI.Colors.GREEN : ANSI.Background.GREEN,
                ANSI.Colors.ORANGE : ANSI.Background.ORANGE,
                ANSI.Colors.RED : ANSI.Background.RED
            }
        
            background_foreground_mapping = {v: k for k, v in foreground_background_mapping.items()}
            
            if color_code in foreground_background_mapping:
                self.inverse = foreground_background_mapping[color_code]
            elif color_code in background_foreground_mapping:
                self.inverse = background_foreground_mapping[color_code]
            else:
                print(f"FAILED TO FIND INVERSE OF COLOR CODE {color_code} - RETURNING SAME")
                self.inverse = color_code

        def __str__(self):
            return self.inverse

    @staticmethod
    def stripper(string)->str:
        """
        Remove all ANSI Escape code sequences from a string
        """
        ansi_escape =re.compile(r'(\x9B|\x1B\[)[0-?]*[ -\/]*[@-~]')
        return ansi_escape.sub('', str(string))

    @staticmethod
    def center(string:str,
                    width:int,
                    padding:str=" ",
                    padding_color:str="",
                    padding_formatting:str|List[str]="",
                    edge_left:str="",
                    edge_right:str="")->str:
        """
        Similar to string.center, but correcly calculate centering by ignoring ascii characters
        Supports any printable characters and can add ANSI ANSI.Colors.and formatting to the padding.
        edge_left and edge_right are characters that can be inserted between the string and the padding.
        This is particularly useful to create complex shapes.
        """
        padded_string = ""
        STOP = ANSI.Formatting.STOP
        COLOR = padding_color
        FORMATTING = padding_formatting
        if type(padding_formatting) is list:
            FORMATTING = "".join(str(padding_formatting))
        
        diff_width = width - len(ANSI.stripper(string))
        remainder = diff_width % 2
        if remainder == 0:
            l_pad = r_pad = int(diff_width/2)
        else:
            l_pad = int(diff_width/2) + remainder
            r_pad = int(diff_width - l_pad)

        if edge_left:
            l_pad -= 1
        if edge_right:
            r_pad -= 1

        padded_string = f"{COLOR}{FORMATTING}{padding*l_pad}{edge_left}{STOP}{string}{COLOR}{FORMATTING}{edge_right}{padding*r_pad}{STOP}"

        return padded_string

class DialogSection(NamedTuple):
    section_name: str | None
    color: str
    message: str


class Dialog:
    def __init__(self, border_color:str, sections:List[DialogSection]):
        dialog:str = ""
        BOLD = ANSI.Formatting.BOLD
        ITALICS = ANSI.Formatting.ITALICS
        STOP = ANSI.Formatting.STOP
        INVERSE = ANSI.Formatting.INVERSE


        for index, section in enumerate(sections):
            section_name = "" if not section.section_name else section.section_name

            if index == 0:
                # Trick to keep the border_color, then switch to the section color and bac
                section_name = f"{STOP}{BOLD}{section.color}{section_name}{STOP}"
                # 77 and not 78 as it looks slightly better when using emojis 
                edge = "─"*(len(ANSI.stripper(section_name)))
                section_name = ANSI.center(section_name, 78, "═", border_color, BOLD, "╡", "╞")


                upper_edge_line = border_color + "┌" +  edge + "┐"
                upper_edge = f"{ANSI.center(upper_edge_line, 80)}{STOP}"
                bottom_edge_line = border_color + "└" + edge + "┘"
                bottom_edge = f"{BOLD}{border_color}║{ANSI.center(bottom_edge_line, 78)}{BOLD}{border_color}║"

                top_border = f"{BOLD}{border_color}╔{STOP}{section_name}{BOLD}{border_color}╗{STOP}"

                dialog += upper_edge + "\n" + top_border + "\n" + bottom_edge + "\n"

                messages = textwrap.wrap(section.message, 76)
                for message in messages:
                    line = f"{BOLD}{border_color}║{STOP}{ITALICS}{section.color} {message.center(76,' ')} {STOP}{BOLD}{border_color}║{STOP}"
                    dialog += line + "\n"

            else:                
                # Trick to keep the border_color, then switch to the section color and bac
                section_name = f"{STOP}{BOLD} {ANSI.Inverse(section.color)}{section_name}{STOP} {border_color}"
                section_name = ANSI.center(section_name, 78, "─", border_color, BOLD, edge_left="┤", edge_right="├")

                top_border = f"{BOLD}{border_color}╟{STOP}{section_name}{BOLD}{border_color}╢{STOP}"
                
                dialog += top_border + "\n"

                messages = textwrap.wrap(section.message, 76)
                for message in messages:
                    line = f"{BOLD}{border_color}║{STOP}{section.color} {message.ljust(76,' ')} {STOP}{BOLD}{border_color}║{STOP}"
                    dialog += line + "\n"


        dialog += f"{BOLD}{border_color}╚{'═'*78}╝{STOP}"

        self.dialog = dialog

    def __str__(self):
        return self.dialog

class LogSegment(NamedTuple):
    message:str
    segment_color: str = ""
    segment_name:str = ""


class SegmentedLog:
    
    def __init__(self, segments:List[LogSegment],
                    accent:str,
                    header:str,
                    width:int,
                    margin:int):
        
        STOP = ANSI.Formatting.STOP
        ITALICS = ANSI.Formatting.ITALICS
        log_data = str()
        # Remove segments with empty messages
        segments = [s for s in segments if s.message]
        master_header = f"{STOP}[{accent}{header}{STOP}]" + f"{accent}{'─'*(margin-(len(header)+4))}{STOP}"
        
        for segment in segments: 
            if segment.segment_name:
                ansi_header = f"─┤{STOP}{segment.segment_color}{ITALICS} {segment.segment_name} {STOP}{accent}├{STOP} {segment.segment_color}"
            else:
                ansi_header = f"{STOP} "

            if len(segments) == 1 and (len(segment.message) < (width - margin - len(ansi_header))):
                cursor = "─"
            elif segment == segments[0]:
                cursor = "┬"
            elif len(segment.message) < (60 - len(ANSI.stripper(ansi_header))) and segment == segments[-1] and len(segments) > 1:
                cursor = "└"
            else:
                cursor = "├"
            
            ansi_header= f"{STOP}{accent}{cursor}{ansi_header}"
            header = ANSI.stripper(ansi_header)
            segment_message = header + str(segment.message)
            segment_messages = textwrap.wrap(segment_message,(width - margin))
            message_section = str()
            for line in segment_messages:
                if line == segment_messages[0]:
                    message_section += line + "\n"
                elif line == segment_messages[-1] and segment == segments[-1]:
                    message_section += f"{STOP}{accent}└{STOP}{segment.segment_color} {line}\n"
                else:
                    message_section += f"{STOP}{accent}├{STOP}{segment.segment_color} {line}\n"

            log_data += message_section.replace(header, ansi_header)
        log_data = master_header + f"\n{' '*(margin-2)}".join(log_data.split("\n"))
        self.log_data = log_data.rstrip().rstrip("\n")

    def __str__(self):
        return self.log_data


def log(
    category: Literal[
        "ONGOING",
        "SUCCESS",
        "WARNING",
        "INFO",
        "FAILURE",
        "FATAL",
        "DEBUG",
        "SKIP",
        "TITLE",
    ],
    message: str,
    highlight: str = "",
    advice: str = "",
    icon: str = "",
):

    # Escape code sequences for formatting
    PURPLE = ANSI.Colors.PURPLE
    BLUE = ANSI.Colors.BLUE
    CYAN = ANSI.Colors.CYAN
    GREEN = ANSI.Colors.GREEN
    ORANGE = ANSI.Colors.ORANGE
    RED = ANSI.Colors.RED
    BOLD = ANSI.Formatting.BOLD
    ITALICS = ANSI.Formatting.ITALICS
    UNDERLINE = ANSI.Formatting.UNDERLINE
    STOP = ANSI.Formatting.STOP

    message = str(message)
    accent = str()
    header = str()

    match category:
        case "ONGOING":
            accent = ORANGE
            header = "ONGOING..."
        case "SUCCESS":
            accent = GREEN
            header = "SUCCESS"
        case "WARNING":
            accent = ORANGE
            header = "WARNING"
        case "INFO":
            accent = BLUE
            header = "INFORMATIONAL"
        case "FAILURE":
            accent = RED
            header = "FAILURE"
        case "DEBUG":
            accent = PURPLE
            header = "DEBUG"
        case "SKIP":
            accent = CYAN
            header = "SKIPPED"
        case "TITLE":
            message = f"{PURPLE}{message}{STOP}"
            message = ANSI.center(message, 80, padding="~", padding_color=ORANGE)
        case _:
            header = category

    
    if category == "FATAL":
        sections = []
        sections.append(DialogSection(section_name=f" {ORANGE}!!{STOP}{RED} FATAL ERROR {ORANGE}!!{STOP} ",
                          color=ANSI.Colors.RED,
                          message=message))
        if highlight:
            sections.append(DialogSection(section_name=f"DETAILS",
                            color=ANSI.Colors.PURPLE,
                            message=highlight))

        if advice:
            sections.append(DialogSection(section_name=f"ADVICE",
                            color=ANSI.Colors.CYAN,
                            message=advice))

        log_message = Dialog(border_color=ANSI.Colors.RED, sections=sections)

    else:
        if category == "TITLE":
            log_message = message
        else:

            log_message = SegmentedLog(segments=[
                LogSegment(message=message, segment_color="", segment_name=""), 
                LogSegment(message=highlight, segment_color=PURPLE, segment_name="Detail"), 
                LogSegment(message=advice, segment_color=CYAN, segment_name="Advice"),
            ],
            accent=accent,
            header=header,
            width=80,
            margin=20)

    #Using an envvar allows to get around circular dependency issues
    if os.getenv("TIDE_DEBUG_ENABLED") or os.environ.get("TERM_PROGRAM") == "vscode":
        log_message = ANSI.stripper(log_message)

    if category == "DEBUG" and os.getenv("TIDE_DEBUG_ENABLED"):
        print(log_message, flush=True)

    elif category != "DEBUG":
        print(log_message, flush=True)


def print_banner():
    BLUE = ANSI.Colors.DARK_BLUE
    YELLOW = ANSI.Colors.ORANGE
    STOP = ANSI.Formatting.STOP
    ITALICS = ANSI.Formatting.ITALICS
    BOLD = ANSI.Formatting.BOLD

    coretide = f"{BLUE}Core{YELLOW}TIDE"

    intro = f"""
{BLUE}            :--==-:.       
{BLUE}         -+*###*####*+:      
{BLUE}       -=:   {YELLOW}.:  {BLUE}=-+*##*.              
{BLUE}     -=.  {YELLOW}.:.     {BLUE}.+.*=:+             {STOP}{BOLD}Powered by {coretide}{STOP}
{BLUE}  .-+:  {YELLOW}.-:  :  . {BLUE}-- :  .     
{BLUE}+*#+   {YELLOW}-=.  -:  : {BLUE}:=              {STOP}{ITALICS}The engine powering OpenTIDE Instances{STOP}    
{BLUE}#*-  {YELLOW}.==.  :=  .-  {BLUE}+            {STOP}{ITALICS}Part of the OpenThreat Informed Detection Engineering Initiative{STOP}
{BLUE}:   {YELLOW}:==:   =-  .=. {BLUE}.+      
   {YELLOW}:==-   :=-   --  {BLUE}.+:    {STOP}https://code.europa.eu/ec-digit-s2/opentide/coretide
  {YELLOW}:===.   ==-   :=-   {BLUE}:=-
 {YELLOW}.====    ===.   -=-.    {STOP}
"""

    return intro


coretide_intro = print_banner