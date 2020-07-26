using System.IO;

namespace SecurityKey
{
    public interface IDevice
    {
        Stream OpenConnection();
    }
}
