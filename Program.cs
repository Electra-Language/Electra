using System;
using System.Runtime.InteropServices;

namespace Electra {
    
    internal class Program {

        public static void Main(string[] args) {

            Console.WriteLine(Marshal.SizeOf(typeof(PEHeader)).ToString());

        }

    }

}