import logging
from abc import ABC
from typing import List, Optional, Callable, Tuple

from bs4 import BeautifulSoup, Tag

from credsweeper.common.constants import MAX_LINE_LENGTH
from credsweeper.credentials.candidate import Candidate
from credsweeper.deep_scanner.abstract_scanner import AbstractScanner

from credsweeper.file_handler.string_content_provider import StringContentProvider
from credsweeper.logger import TRACE

logger = logging.getLogger(__name__)


class HtmlScanner(AbstractScanner, ABC):
    """Implements html scanning if possible"""

    @staticmethod
    def match(data: bytes | bytearray) -> bool:
        """Used to detect html format. Suppose, invocation of is_xml() was True before."""
        for opening_tag, closing_tag in [(b"<html", b"</html>"), (b"<body", b"</body>"), (b"<table", b"</table>"),
                                         (b"<p>", b"</p>"), (b"<span>", b"</span>"), (b"<div>", b"</div>"),
                                         (b"<li>", b"</li>"), (b"<ol>", b"</ol>"), (b"<ul>", b"</ul>"),
                                         (b"<th>", b"</th>"), (b"<tr>", b"</tr>"), (b"<td>", b"</td>")]:
            opening_pos = data.find(opening_tag, 0, MAX_LINE_LENGTH)
            if 0 <= opening_pos < data.find(closing_tag, opening_pos):
                # opening and closing tags were found - suppose it is an HTML
                return True
        return False

    def _check_multiline_cell(self, cell: Tag) -> Optional[Tuple[int, str]]:
        """multiline cell will be analyzed as text or return single line from cell
        returns line number and one line for analysis
        If there are no text or the text will be analyzed as multiline - it returns None"""
        # use not stripped get_text, otherwise all format is cleaned
        cell_text = cell.get_text()
        cell_lines = cell_text.splitlines()
        line_numbers: List[int] = []
        stripped_lines: List[str] = []
        for offset, line in enumerate(cell_lines):
            if stripped_line := line.strip():
                line_numbers.append(cell.sourceline + offset)
                stripped_lines.append(stripped_line)

        if not stripped_lines:
            return None
        if 1 == len(stripped_lines):
            return line_numbers[0], stripped_lines[0]
        # otherwise the cell will be analyzed as multiline text
        self.line_numbers.extend(line_numbers)
        self.lines.extend(stripped_lines)
        self.__html_lines_size += sum(len(x) for x in stripped_lines)
        return None

    @staticmethod
    def simple_html_representation(html: BeautifulSoup) -> Tuple[List[int], List[str], int]:
        """simple parse as it is displayed to user and appends the lines"""
        line_numbers: List[int] = []
        lines: List[str] = []
        lines_size = 0
        # use dedicated variable to deal with yapf and flake
        tags_to_split = [
            "p", "br", "tr", "li", "ol", "h1", "h2", "h3", "h4", "h5", "h6", "blockquote", "pre", "div", "th", "td"
        ]
        for p in html.find_all(tags_to_split):
            p.append('\t')
        html_lines = html.get_text().splitlines()
        for line_number, doc_line in enumerate(html_lines):
            line = doc_line.strip()
            if line:
                line_numbers.append(line_number + 1)
                lines.append(line)
                lines_size += len(line)
        return line_numbers, lines, lines_size

    @staticmethod
    def _table_depth_reached(table: Tag, depth: int) -> bool:
        if parent := table.parent:
            if isinstance(parent, BeautifulSoup):
                return False
            if 0 > depth:
                return True
            if "table" == parent.name:
                depth -= 1
            return HtmlScanner._table_depth_reached(parent, depth)
        return True

    def _table_representation(
            self,  #
            table: Tag,  #
            depth: int,  #
            recursive_limit_size: int,  #
            keywords_required_substrings_check: Callable[[str], bool]):
        """
        transform table if table cell is assigned to header cell
        make from cells a chain like next is assigned to previous
        """
        if HtmlScanner._table_depth_reached(table, depth):
            logger.warning("Recursive depth limit was reached during HTML table combinations")
            return
        table_header: Optional[List[Optional[str]]] = None
        rowspan_columns = []
        for tr in table.find_all("tr"):
            if recursive_limit_size < self.__html_lines_size:
                # weird tables may lead to oversize memory
                break
            record_numbers = []
            record_lines = []
            record_leading = None
            if table_header is None:
                table_header = []
                # first row in table may be a header with <td> and a style, but search <th> too
                for cell in tr.find_all(["th", "td"]):
                    if recursive_limit_size < self.__html_lines_size:
                        # keep the duplicates for early breaks!
                        break
                    colspan_header = int(cell.get("colspan", 1))
                    if td_numbered_line := self._check_multiline_cell(cell):
                        td_text = td_numbered_line[1]
                        td_text_has_keywords = keywords_required_substrings_check(td_text.lower())
                        rowspan_header = int(cell.get("rowspan", 1))
                        for _ in range(colspan_header):
                            rowspan_columns.append(rowspan_header)
                            if td_text_has_keywords:
                                table_header.append(td_text)
                                self.__html_lines_size += len(td_text)
                            else:
                                table_header.append(None)
                            # approximate size for auxiliary objects (pointer, types, etc.)
                            self.__html_lines_size += 128
                            if recursive_limit_size < self.__html_lines_size:
                                break
                        if record_leading is None:
                            if td_text_has_keywords:
                                record_leading = td_text
                            else:
                                record_leading = ""
                        else:
                            record_numbers.append(td_numbered_line[0])
                            record_lines.append(f"{record_leading} : {td_text}")
                            self.__html_lines_size += 128 + len(td_text)

                        # add single text to lines for analysis
                        self.line_numbers.append(td_numbered_line[0])
                        self.lines.append(td_text)
                        self.__html_lines_size += 128 + len(td_text)
                    else:
                        # empty cell or multiline cell
                        # number of columns is defined with header only
                        rowspan_header = int(cell.get("rowspan", 1))
                        for _ in range(colspan_header):
                            rowspan_columns.append(rowspan_header)
                            table_header.append(None)
                            self.__html_lines_size += 128
                            if recursive_limit_size < self.__html_lines_size:
                                break
            else:
                header_pos = 0
                # not a first line in table - may be combined with a header
                for cell in tr.find_all("td"):
                    if recursive_limit_size < self.__html_lines_size:
                        # keep the duplicates for early breaks!
                        break
                    while header_pos < len(rowspan_columns) and 1 < rowspan_columns[header_pos]:
                        rowspan_columns[header_pos] -= 1
                        header_pos += 1
                    colspan_cell = int(cell.get("colspan", 1))
                    rowspan_cell = int(cell.get("rowspan", 1))
                    for i in range(header_pos, header_pos + colspan_cell):
                        if i < len(rowspan_columns):
                            rowspan_columns[i] += rowspan_cell - 1
                    if td_numbered_line := self._check_multiline_cell(cell):
                        td_text = td_numbered_line[1]
                        if record_leading is None:
                            td_text_has_keywords = keywords_required_substrings_check(td_text.lower())
                            if td_text_has_keywords:
                                record_leading = td_text
                            else:
                                record_leading = ""
                        elif record_leading:
                            record_numbers.append(td_numbered_line[0])
                            record_line = f"{record_leading} : {td_text}"
                            record_lines.append(record_line)
                            self.__html_lines_size += 128 + len(record_line)
                            if recursive_limit_size < self.__html_lines_size:
                                break
                        if header_pos < len(table_header):
                            if header_text := table_header[header_pos]:
                                self.line_numbers.append(td_numbered_line[0])
                                self.lines.append(f"{header_text} : {td_text}")
                                self.__html_lines_size += 128 + len(td_text)
                    else:
                        # empty cell or multiline cell
                        table_header.append(None)
                        self.__html_lines_size += 64
                    header_pos += colspan_cell
            if record_lines:
                # add combinations with left column
                self.line_numbers.extend(record_numbers)
                self.lines.extend(record_lines)
                self.__html_lines_size += sum(len(x) for x in record_lines)

    def _html_tables_representation(
            self,  #
            html: BeautifulSoup,  #
            depth: int,  #
            recursive_limit_size: int,  #
            keywords_required_substrings_check: Callable[[str], bool]):
        """Iterates for all tables in html to explore cells and their combinations"""
        depth -= 1
        if 0 > depth:
            return
        for table in html.find_all("table"):
            if recursive_limit_size < self.__html_lines_size:
                logger.warning("Recursive size limit was reached during HTML table combinations")
                break
            self._table_representation(table, depth, recursive_limit_size, keywords_required_substrings_check)

    def represent_as_html(
            self,  #
            depth: int,  #
            recursive_limit_size: int,  #
            keywords_required_substrings_check: Callable[[str], bool]) -> Optional[bool]:
        """Tries to read data as html

        Return:
             True if reading was successful
             False if no data found
             None if the format is not acceptable

        """
        try:
            if "</" in self.text and ">" in self.text:
                if html := BeautifulSoup(self.text, features="html.parser"):
                    line_numbers, lines, lines_size = self.simple_html_representation(html)
                    self.line_numbers.extend(line_numbers)
                    self.lines.extend(lines)
                    self.__html_lines_size += lines_size
                    # apply recursive_limit_size/2 to reduce extra calculation
                    # of all accompanying losses per objects allocation
                    self._html_tables_representation(html, depth, recursive_limit_size >> 1,
                                                     keywords_required_substrings_check)
                    logger.log(TRACE, "CONVERTED from html")
            else:
                logger.log(TRACE, "Data do not contain specific tags - weak HTML")
        except Exception as exc:  # pylint: disable=broad-exception-caught
            # fallback
            logger.log(TRACE, "Cannot parse as HTML %s:%s %s", type(exc), exc, self.descriptor)
        else:
            return bool(self.lines and self.line_numbers)
        return None

    def data_scan(
            self,  #
            data_provider: DataContentProvider,  #
            depth: int,  #
            recursive_limit_size: int) -> Optional[List[Candidate]]:
        """Tries to represent data as html text and scan as text lines"""
        if result := self.represent_as_html(depth, recursive_limit_size,
                                            self.scanner.keywords_required_substrings_check):
            string_data_provider = StringContentProvider(lines=data_provider.lines,
                                                         line_numbers=data_provider.line_numbers,
                                                         file_path=data_provider.file_path,
                                                         file_type=data_provider.file_type,
                                                         info=f"{data_provider.info}|HTML")
            return self.scanner.scan(string_data_provider)
        return None if result is None else []
