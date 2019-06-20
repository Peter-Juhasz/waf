using Microsoft.Extensions.Primitives;
using System;
using System.Collections.Generic;
using System.Text.Encodings.Web;

namespace Firewall
{
    public static class FastHtmlParser
    {
        public static int FindTagIndex(string html, string tag, int startIndex = 0)
        {
            while (startIndex + tag.Length <= html.Length)
            {
                int index = html.IndexOf($"<{tag}", startIndex, StringComparison.OrdinalIgnoreCase);
                if (index == -1)
                {
                    return -1;
                }

                if (html.Length >= index + tag.Length)
                {
                    char next = html[index + tag.Length + 1];
                    if (next == ' ' || next == '>' || next == '\n' || next == '\r')
                    {
                        return index;
                    }
                    else
                    {
                        startIndex = index + 1;
                    }
                }
            }

            return -1;
        }

        public static int FindAttributeIndex(string html, string attribute, int startIndex = 0)
        {
            while (startIndex + attribute.Length <= html.Length)
            {
                int index = html.IndexOf($"{attribute}=", startIndex, StringComparison.OrdinalIgnoreCase);
                if (index == -1)
                {
                    return -1;
                }

                if (html.Length >= index + attribute.Length)
                {
                    char next = html[index + attribute.Length + 1];
                    if (next == '"' || next == '\'')
                    {
                        var lastTagDelimiterIndex = html.LastIndexOfAny(new[] { '<', '>' }, index);
                        if (lastTagDelimiterIndex != -1 && html[lastTagDelimiterIndex] == '<')
                        {
                            return index;
                        }
                        else
                        {
                            startIndex = index + 1;
                        }
                    }
                    else
                    {
                        startIndex = index + 1;
                    }
                }
            }

            return -1;
        }

        public static int FindEndOfOpenTag(string html, int tagStartIndex)
        {
            int idx = html.IndexOf('>', tagStartIndex);
            if (idx == -1)
                return html.Length;
            return idx;
        }

        public static IEnumerable<int> FindAllTagIndexes(string html, string tag)
        {
            int index = FindTagIndex(html, tag);
            while (index != -1)
            {
                yield return index;
                index = FindTagIndex(html, tag, index + 1);
            }
        }

        public static IEnumerable<int> FindAllAttributeIndexes(string html, string attribute)
        {
            int index = FindAttributeIndex(html, attribute);
            while (index != -1)
            {
                yield return index;
                index = FindAttributeIndex(html, attribute, index + 1);
            }
        }

        public static int FindClosePairFlatIndex(string html, string tag, int openTagIndex)
        {
            return html.IndexOf($"</{tag}>", openTagIndex);
        }

        public static int FindOpenPairFlatIndex(string html, string tag, int closeTagIndex)
        {
            while (closeTagIndex > 0)
            {
                int index = html.LastIndexOf($"<{tag}", closeTagIndex, StringComparison.OrdinalIgnoreCase);
                if (index == -1)
                {
                    return -1;
                }

                if (html.Length >= index + tag.Length)
                {
                    char next = html[index + tag.Length + 1];
                    if (next == ' ' || next == '>' || next == '\n' || next == '\r')
                    {
                        return index;
                    }
                    else
                    {
                        closeTagIndex = index;
                    }
                }
            }

            return -1;
        }

        public static int FindAttributeNameIndex(string html, string attribute, int tagStartIndex)
        {
            int endIndex = html.IndexOf('>', tagStartIndex);

            while (tagStartIndex + attribute.Length <= html.Length)
            {
                var index = html.IndexOf(attribute, tagStartIndex, StringComparison.OrdinalIgnoreCase);
                if (index == -1)
                {
                    return -1;
                }
                if (endIndex != -1 && index > endIndex)
                {
                    return -1;
                }

                if (html.Length >= index + attribute.Length)
                {
                    char next = html[index + attribute.Length];
                    if (next == '=' || next == ' ' || next == '>' || next == '\n' || next == '\r')
                    {
                        return index;
                    }
                    else
                    {
                        tagStartIndex = index + 1;
                    }
                }
            }

            return -1;
        }

        public static StringSegment? GetInnerHtml(string html, int tagStartIndex, string tag)
        {
            int openTagEnd = FindEndOfOpenTag(html, tagStartIndex);
            if (openTagEnd == -1)
            {
                return null;
            }

            int closeTag = FindClosePairFlatIndex(html, tag, tagStartIndex);
            if (closeTag == -1)
            {
                closeTag = html.Length;
            }

            return new StringSegment(html, openTagEnd + 1, closeTag - openTagEnd - 1);
        }

        public static StringSegment? GetFullTagSpan(string html, int tagStartIndex, string tag)
        {
            int openTagEnd = FindEndOfOpenTag(html, tagStartIndex);
            if (openTagEnd == -1)
            {
                return null;
            }

            int closeTag = FindClosePairFlatIndex(html, tag, tagStartIndex);
            if (closeTag == -1)
            {
                closeTag = html.Length;
            }

            return new StringSegment(html, tagStartIndex, closeTag + tag.Length + 3 - tagStartIndex);
        }

        public static StringSegment GetAttributeValueAtTag(string html, string attribute, int tagStartIndex)
        {
            int nameIndex = FindAttributeNameIndex(html, attribute, tagStartIndex);
            if (nameIndex + attribute.Length <= html.Length)
            {
                char delimiter = html[nameIndex + attribute.Length];
                if (delimiter != '=')
                {
                    return StringSegment.Empty;
                }

                int valueIndex = nameIndex + attribute.Length + 1;
                char quote = html[valueIndex];
                if (quote == '"')
                {
                    int endIndex = html.IndexOfAny(new char[] { '"' }, nameIndex + attribute.Length + 2);
                    return new StringSegment(html, valueIndex + 1, endIndex - valueIndex - 1);
                }
                else if (quote == '\'')
                {
                    int endIndex = html.IndexOfAny(new char[] { '\'' }, nameIndex + attribute.Length + 2);
                    return new StringSegment(html, valueIndex + 1, endIndex - valueIndex - 1);
                }
                else if (!Char.IsWhiteSpace(quote))
                {
                    int endIndex = html.IndexOfAny(new char[] { ' ', '>', '\r', '\n', '\t' }, nameIndex + attribute.Length + 2);
                    return new StringSegment(html, valueIndex, endIndex - valueIndex);
                }
            }

            return StringSegment.Empty;
        }

        public static StringSegment GetAttributeValueAtName(string html, string attribute, int attributeNameIndex)
        {
            int valueIndex = attributeNameIndex + attribute.Length + 1;
            char quote = html[valueIndex];
            if (quote == '"')
            {
                int endIndex = html.IndexOfAny(new char[] { '"' }, attributeNameIndex + attribute.Length + 2);
                return new StringSegment(html, valueIndex + 1, endIndex - valueIndex - 1);
            }
            else if (quote == '\'')
            {
                int endIndex = html.IndexOfAny(new char[] { '\'' }, attributeNameIndex + attribute.Length + 2);
                return new StringSegment(html, valueIndex + 1, endIndex - valueIndex - 1);
            }
            else if (!Char.IsWhiteSpace(quote))
            {
                int endIndex = html.IndexOfAny(new char[] { ' ', '>', '\r', '\n', '\t' }, attributeNameIndex + attribute.Length + 2);
                return new StringSegment(html, valueIndex, endIndex - valueIndex);
            }

            return StringSegment.Empty;
        }

        public static StringSegment GetAttributeNameFromValueIndex(string html, int attributeValueIndex)
        {
            int delimiterIndex = html.LastIndexOfAny(new[] { '=', '>', '<' }, attributeValueIndex);
            if (delimiterIndex == -1)
            {
                return StringSegment.Empty;
            }

            char ch = html[delimiterIndex];
            if (ch == '>' || ch == '<')
            {
                return StringSegment.Empty;
            }

            int separatorIndex = html.LastIndexOf(' ', delimiterIndex);
            if (separatorIndex == -1)
            {
                return StringSegment.Empty;
            }

            return new StringSegment(html, separatorIndex + 1, delimiterIndex - separatorIndex - 1);
        }

        public static int FindOpenTagAtAttribute(string html, int attributeIndex)
        {
            return html.LastIndexOf('<', attributeIndex);
        }

        public static int FindCommentIndex(string html, int startIndex = 0)
        {
            return html.IndexOf("<!--", startIndex);
        }

        public static StringSegment GetCommentFullSpan(string html, int commentStartIndex)
        {
            int end = html.IndexOf("-->", commentStartIndex + "<!--".Length);
            if (end == -1)
            {
                return StringSegment.Empty;
            }

            return new StringSegment(html, commentStartIndex, end + "-->".Length - commentStartIndex);
        }

        public static IEnumerable<int> FindAllCommentIndexes(string html)
        {
            int index = FindCommentIndex(html);
            while (index != -1)
            {
                yield return index;
                index = FindCommentIndex(html, index + 1);
            }
        }

        public static IEnumerable<StringSegment> FindAllComments(string html)
        {
            int index = FindCommentIndex(html);
            while (index != -1)
            {
                var segment = GetCommentFullSpan(html, index);
                if (segment.Length != 0)
                {
                    yield return segment;
                }

                index = FindCommentIndex(html, segment.Offset + segment.Length);
            }
        }

        public static TextChange CreateInsertAttributeChange(string html, int tagStartIndex, string tag, string name, string value)
        {
            return TextChange.Insert(html, tagStartIndex + tag.Length + 1, $" {name}=\"{HtmlEncoder.Default.Encode(value)}\" ");
        }

        public static TextChange CreateInsertAttributeChange(string html, int tagStartIndex, string name, string value)
        {
            int separatorIndex = html.IndexOf(' ', tagStartIndex);

            return TextChange.Insert(html, separatorIndex, $" {name}=\"{HtmlEncoder.Default.Encode(value)}\" ");
        }
    }
}
