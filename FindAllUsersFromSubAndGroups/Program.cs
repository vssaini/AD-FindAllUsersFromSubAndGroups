using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.Security.Principal;
using System.Text.RegularExpressions;

namespace FindAllUsersFromSubAndGroups
{
	internal static class Program
	{
		/// <summary>
		/// Get or set the total users discovered in group.
		/// </summary>
		private static int TotalUsers { get; set; }

		private static void Main()
		{
			// Ref - https://stackoverflow.com/questions/3665487/get-members-of-an-active-directory-group-recursively-i-e-including-subgroups

			const string rootPath = @"LDAP://DC=Domain,DC=Com";
			const string groupDn = @"CN = 1000PlusTest,OU = Groups,DC = domain,DC = com";

			// Let's measure time too for performance part.
			var stopwatch = new Stopwatch();
			stopwatch.Start();

			using (var searchRoot = new DirectoryEntry(rootPath))
			{
				//var users = GetUsersRecursively(searchRoot, groupDn);
				var users = GetUsersByFilteringThroughChainedObjects(searchRoot);
				foreach (var user in users)
				{
					Console.WriteLine((string)user.Properties["sAMAccountName"][0]);
					TotalUsers++;
				}
			}

			GetAllUsersBySam("1000PlusTest", "domain.com");
			stopwatch.Stop();

			const long ticksPerMicrosecond = 10;
			var microseconds = stopwatch.ElapsedTicks / ticksPerMicrosecond;
			var nanoseconds = stopwatch.Elapsed.TotalMilliseconds * 1000000;

			// Show information to console
			Console.ForegroundColor = ConsoleColor.Green;
			Console.WriteLine(Environment.NewLine);
			Console.WriteLine("Total {0} objects were retrieved from AD in {1} min {2} s {3} ms {4} us and {5} ns.", TotalUsers, stopwatch.Elapsed.Minutes, stopwatch.Elapsed.Seconds, stopwatch.Elapsed.Milliseconds, microseconds, nanoseconds);
			Console.ReadLine();
		}

		/// <summary>
		/// Get all users as per System.Account.Management class.
		/// </summary>
		/// <param name="groupName"></param>
		/// <param name="domainName"></param>
		private static void GetAllUsersBySam(string groupName, string domainName)
		{
			var ctx = new PrincipalContext(ContextType.Domain, domainName);
			var grp = GroupPrincipal.FindByIdentity(ctx, IdentityType.Name, groupName);

			if (grp != null)
			{
				foreach (var p in grp.GetMembers(true))
				{
					Console.WriteLine(p.Name);
					TotalUsers++;
				}

				grp.Dispose();
				ctx.Dispose();
			}
			else
			{
				Console.WriteLine("\nWe did not  find that group in the domain.");
			}
		}

		/// <summary>
		/// Get users filtered by chain objects. For more, check out<a href="https://msdn.microsoft.com/en-us/library/aa746475(VS.85).aspx" target="_blank">Search Filter Syntax</a>.
		/// </summary>
		/// <param name="entry"></param>
		/// <returns></returns>
		private static IEnumerable<SearchResult> GetUsersByFilteringThroughChainedObjects(DirectoryEntry entry)
		{
			using (var searcher = new DirectorySearcher(entry))
			{
				// If the directory entry is a group
				if (entry.SchemaClassName == "group")
				{
					// Get the group RID
					var groupSid = new SecurityIdentifier((byte[])entry.Properties["objectSid"][0], 0);
					var matchGroupRid = Regex.Match(groupSid.Value, @".*-(\d+)",
						RegexOptions.Singleline | RegexOptions.IgnoreCase);
					var groupRid = matchGroupRid.Groups[1].Value;

					var groupFilter = string.Format("(|(memberOf:1.2.840.113556.1.4.1941:={0})(primaryGroupID={1}))",
						entry.Properties["distinguishedName"][0], groupRid);

					searcher.Filter =
						"(&((|(memberOf:1.2.840.113556.1.4.1941:=CN=1000PlusTest,OU=Groups,DC=domain,DC=com)))((|(&(objectClass=user)(!(objectClass=computer))))))";

					searcher.PropertiesToLoad.Clear();
					searcher.PropertiesToLoad.AddRange(new[]
					{
						"objectGUID",
						"sAMAccountName",
						"distinguishedName"
					});
					searcher.Sort = new SortOption("sAMAccountName", SortDirection.Ascending);
					searcher.PageSize = 1000;
					searcher.SizeLimit = 0;
					foreach (SearchResult result in searcher.FindAll())
					{
						yield return result;
					}
				}
			}
		}

		public static IEnumerable<SearchResult> GetUsersRecursively(DirectoryEntry searchRoot, string groupDn)
		{
			var searchedGroups = new List<string>();
			var searchedUsers = new List<string>();
			return GetUsersRecursively(searchRoot, groupDn, searchedGroups, searchedUsers);
		}

		private static IEnumerable<SearchResult> GetUsersRecursively(
			DirectoryEntry searchRoot,
			string groupDn,
			ICollection<string> searchedGroups,
			ICollection<string> searchedUsers)
		{
			foreach (var subGroup in GetMembers(searchRoot, groupDn, "group"))
			{
				var subGroupName = ((string)subGroup.Properties["sAMAccountName"][0]).ToUpperInvariant();
				if (searchedGroups.Contains(subGroupName))
				{
					continue;
				}
				searchedGroups.Add(subGroupName);
				var subGroupDn = (string)subGroup.Properties["distinguishedName"][0];
				foreach (var user in GetUsersRecursively(searchRoot, subGroupDn, searchedGroups, searchedUsers))
				{
					yield return user;
				}
			}
			foreach (var user in GetMembers(searchRoot, groupDn, "user"))
			{
				var userName = ((string)user.Properties["sAMAccountName"][0]).ToUpperInvariant();
				if (searchedUsers.Contains(userName))
				{
					continue;
				}
				searchedUsers.Add(userName);
				yield return user;
			}
		}

		private static IEnumerable<SearchResult> GetMembers(DirectoryEntry searchRoot, string groupDn, string objectClass)
		{
			using (var searcher = new DirectorySearcher(searchRoot))
			{
				searcher.Filter = "(&(objectClass=" + objectClass + ")(memberOf=" + groupDn + "))";
				searcher.PropertiesToLoad.Clear();
				searcher.PropertiesToLoad.AddRange(new[] {
				"objectGUID",
				"sAMAccountName",
				"distinguishedName"});
				searcher.Sort = new SortOption("sAMAccountName", SortDirection.Ascending);
				searcher.PageSize = 1000;
				searcher.SizeLimit = 0;
				foreach (SearchResult result in searcher.FindAll())
				{
					yield return result;
				}
			}
		}
	}

}
