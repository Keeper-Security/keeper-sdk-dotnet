using CommandLine;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Cli
{
    public class ParseableCommandMeta<T> : ICommandMeta where T : class
    {
        public int Order { get; set; }

        public string Description { get; set; }

        protected T ParseArguments(string args)
        {
            var res = Parser.Default.ParseArguments<T>(args.TokenizeArguments());
            T options = null;
            res.WithParsed(o => { options = o; });
            return options;
        }
    }

    public class ParseableCommand<T> : ParseableCommandMeta<T>, ICommand where T : class
    {
        public Func<T, Task> Action { get; set; }

        public Task ExecuteCommand(string args)
        {
            var options = ParseArguments(args);
            return options != null ? Action?.Invoke(options) : Task.CompletedTask;
        }
    }

    public sealed class ParsebleVerbCommand : ICommandMeta, ICommand
    {
        private readonly List<Tuple<Type, Func<object, Task>>> _verbs = new List<Tuple<Type, Func<object, Task>>>();
        public int Order { get; set; }

        public string Description { get; set; }

        public void AddVerb<T>(Func<T, Task> action)
        {
            _verbs.Add(Tuple.Create<Type, Func<object, Task>>(typeof(T), o => action((T) o)));
        }
        public Task ExecuteCommand(string args)
        {
            var result = Parser.Default.ParseArguments(args.TokenizeArguments(), _verbs.Select(x => x.Item1).ToArray());
            Tuple<Type, Func<object, Task>> verb = null;
            object options = null;
            result.WithParsed(o =>
            {
                verb = _verbs.FirstOrDefault(x => x.Item1.IsAssignableFrom(o.GetType()));
                options = o;
            });
            return verb != null && options != null ? verb.Item2(options) : Task.CompletedTask;
        }
    }
}
