package com.example.courseworkLuchnetskyi.mapper;

import com.example.courseworkLuchnetskyi.dto.request.TeamRequestDto;
import com.example.courseworkLuchnetskyi.dto.response.TeamResponseDto;
import com.example.courseworkLuchnetskyi.model.Team;
import org.mapstruct.*;

@Mapper(componentModel = "spring")
public interface TeamMapper {
    Team toEntity(TeamRequestDto dto);
    TeamResponseDto toDto(Team team);

    @BeanMapping(nullValuePropertyMappingStrategy = NullValuePropertyMappingStrategy.IGNORE)
    void updateTeamFromDto(@MappingTarget Team team, TeamRequestDto dto);
}
