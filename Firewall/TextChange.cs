using Microsoft.Extensions.Primitives;
using System;
using System.Text;

namespace Firewall
{
    public class TextChange
    {
        public TextChange(string buffer, int offset, int length, string replacement)
        {
            if (offset >= buffer.Length)
            {
                throw new ArgumentOutOfRangeException(nameof(offset));
            }

            if (offset + length > buffer.Length)
            {
                throw new ArgumentOutOfRangeException(nameof(length));
            }

            Buffer = buffer;
            Offset = offset;
            Length = length;
            Replacement = replacement;
        }

        public string Buffer { get; private set; }

        public int Offset { get; private set; }

        public int Length { get; private set; }

        public string Replacement { get; private set; }

        public int Delta => Replacement.Length - Length;

        public int End => Offset + Length;

        public StringSegment Segment => new StringSegment(Buffer, Offset, Length);

        public void Apply(StringBuilder builder)
        {
            if (Length > 0)
            {
                builder.Remove(Offset, Length);
            }

            if (Replacement.Length > 0)
            {
                builder.Insert(Offset, Replacement);
            }
        }

        public void AdjustBy(TextChange edit)
        {
            if (Buffer != edit.Buffer)
            {
                throw new InvalidOperationException($"{nameof(TextChange)} {nameof(Buffer)} doesn't belong to the same {nameof(Buffer)}.");
            }

            if (edit.Offset >= End)
            {
            }
            else if (edit.End <= Offset)
            {
                Offset += edit.Delta;
            }
            else if (edit.Offset <= Offset && edit.End >= End)
            {
                Length = 0;
                Replacement = String.Empty;
            }
            else if (Offset <= edit.Offset && edit.End <= End)
            {
                Length += edit.Delta;
            }
            else if (edit.Offset < Offset && edit.End > Offset && edit.End < End)
            {
                throw new NotImplementedException();
            }
            else if (edit.Offset > Offset && edit.Offset < End && edit.End > End)
            {
                throw new NotImplementedException();
            }
            else
            {
                throw new NotImplementedException();
            }
        }


        public static TextChange Insert(string buffer, int offset, string text) => new TextChange(buffer, offset, 0, text);

        public static TextChange Replace(string buffer, int offset, int length, string text) => new TextChange(buffer, offset, length, text);

        public static TextChange Remove(string buffer, int offset, int length) => new TextChange(buffer, offset, length, String.Empty);
    }
}
