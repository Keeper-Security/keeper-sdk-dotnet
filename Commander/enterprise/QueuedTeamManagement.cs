using KeeperSecurity.Authentication;
using KeeperSecurity.Commands;
using KeeperSecurity.Enterprise;
using System.Threading.Tasks;

namespace Commander.Enterprise
{

    public interface IQueuedTeamDataManagement
    {
        Task QueueUserToTeam(long enterpriseUserId, string teamUid);
    }


    public class QueuedTeamDataManagement : QueuedTeamData, IQueuedTeamDataManagement
    {
        public async Task QueueUserToTeam(long enterpriseUserId, string teamUid)
        {
            var rq = new TeamQueueUserCommand
            {
                TeamUid = teamUid,
                EnterpriseUserId = enterpriseUserId
            };

            await Enterprise.Auth.ExecuteAuthCommand(rq);
            await Enterprise.Load();
        }
    }
}
