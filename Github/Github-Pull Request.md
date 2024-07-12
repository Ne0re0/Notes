You can create a pull request to propose changes you've made to a fork of an upstream repository.

**Requirements**
To successfully create a pull request
- You have to know where you can find the 'target' branch
- You must have a 'dev' branch or a forked repository

# How to create a PR

1. Navigate to the forked repository/feature branch
2. Click **Pull request**
3. Click **New**
4. Select the base repository and the 'feature' repository from the drop down menus
5. Define a title and a description
6. On user-owned forks, if you want to allow anyone with push access to the upstream repository to make changes to your pull request, select **Allow edits from maintainers**.

> [!Warning] If your fork contains GitHub Actions workflows, the option is **Allow edits and access to secrets by maintainers**. Allowing edits on a fork's branch that contains GitHub Actions workflows also allows a maintainer to edit the forked repository's workflows, which can potentially reveal values of secrets and grant access to other branches.

7. Click **Create Pull Request**. To create a draft pull request, use the drop-down and select **Create Draft Pull Request**, then click **Draft Pull Request**. For more information about draft pull requests, see "[About pull requests](https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/proposing-changes-to-your-work-with-pull-requests/about-pull-requests#draft-pull-requests)."


# Resources

- https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/proposing-changes-to-your-work-with-pull-requests/creating-a-pull-request-from-a-fork