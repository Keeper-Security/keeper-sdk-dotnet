using System;
using System.Collections.Generic;
using System.Linq;
using KeeperSecurity.Vault;

namespace KeeperSecurity.Plugins.PAM
{
  /// <summary>
  /// Facade for PAM configuration record pamResources and related fields.
  /// </summary>
  public sealed class PamConfigurationFacade
  {
    private readonly TypedRecord _record;
    private TypedField<FieldPamResources> _pamResources;

    public PamConfigurationFacade(TypedRecord record)
    {
      _record = record ?? throw new ArgumentNullException(nameof(record));
      LoadPamResources();
    }

    public TypedRecord Record => _record;

    public string ControllerUid
    {
      get => GetPamResourcesValue()?.ControllerUid ?? "";
      set
      {
        var resources = EnsurePamResourcesValue();
        resources.ControllerUid = value ?? "";
      }
    }

    public string FolderUid
    {
      get => GetPamResourcesValue()?.FolderUid ?? "";
      set
      {
        var resources = EnsurePamResourcesValue();
        resources.FolderUid = value ?? "";
      }
    }

    public IList<string> ResourceRef
    {
      get
      {
        var refs = GetPamResourcesValue()?.ResourceRef;
        return refs == null ? new List<string>() : refs.ToList();
      }
    }

    public string AdminCredentialRef
    {
      get => GetPamResourcesValue()?.AdminCredentialRef ?? "";
      set
      {
        var resources = EnsurePamResourcesValue();
        resources.AdminCredentialRef = value ?? "";
      }
    }

    public void RemoveResourceRefs(IEnumerable<string> recordUids)
    {
      if (recordUids == null)
      {
        return;
      }

      var resources = EnsurePamResourcesValue();
      var remove = new HashSet<string>(recordUids.Where(x => !string.IsNullOrEmpty(x)), StringComparer.Ordinal);
      resources.ResourceRef = (resources.ResourceRef ?? Array.Empty<string>())
        .Where(x => !remove.Contains(x))
        .ToArray();
    }

    private void LoadPamResources()
    {
      TypedField<FieldPamResources> typedField = null;
      if (VaultDataExtensions.FindTypedField(_record.Fields, new RecordTypeField("pamResources"), out var field))
      {
        typedField = field as TypedField<FieldPamResources>;
      }

      if (typedField == null)
      {
        typedField = VaultDataExtensions.CreateTypedField("pamResources") as TypedField<FieldPamResources>
                     ?? new TypedField<FieldPamResources>("pamResources");
        _record.Fields.Add(typedField);
      }

      _pamResources = typedField;
      if (_pamResources.Count == 0)
      {
        ((ITypedField)_pamResources).AppendValue();
        _pamResources.Values[0] = new FieldPamResources
        {
          ControllerUid = "",
          FolderUid = "",
          ResourceRef = Array.Empty<string>(),
        };
      }
    }

    private FieldPamResources GetPamResourcesValue()
    {
      return _pamResources?.Count > 0 ? _pamResources.Values[0] : null;
    }

    private FieldPamResources EnsurePamResourcesValue()
    {
      if (_pamResources.Count == 0)
      {
        ((ITypedField)_pamResources).AppendValue();
      }

      if (_pamResources.Values[0] == null)
      {
        _pamResources.Values[0] = new FieldPamResources();
      }

      if (_pamResources.Values[0].ResourceRef == null)
      {
        _pamResources.Values[0].ResourceRef = Array.Empty<string>();
      }

      return _pamResources.Values[0];
    }
  }
}
